-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo

import Shirudo.Chain

/-!
The config image activation protocol of rust/src/util/config_update.rs, as `image
update` (`image_update()` of util/image_runtime.c), `image stage`
(`image_stage()`), `status` and `init` (`image_boot()` and
`image_boot_complete()` around the upatch restore and the register
binding in builtin-init.c) drive it. An activation saves the selection
as pending in `state`, extends the config PCR with
`config_measure_event()`, reads the PCR back, appends the event to
`events`, mounts the config and saves the selection complete.
`config_update_check()` lets a command run only when the record is the
last event, of this TPM boot, not pending, and the PCR replays from the
events. `init` records a boot event for the selection, pending or not,
and completes it only at its end. `image stage` saves a consistent
record with another root as `next-boot`; `init` in a later TPM boot
takes that root instead of the record's while the stage still copies the
record (`config_update_staged()`), and an update, or a boot completed in
another TPM boot than the stage's, removes it.

The model is the journal, the TPM boot, which is the TPM's reset count,
every PCR as the list of its extensions, the config mounted and
the one command the lock lets run, at the steps a crash, a failure or a
lost TPM answer can fall between. An error return is a crash, as the C
writes nothing on its error paths but `complete()`'s restore, which is a
step. An extension whose answer is lost is `extend` followed by `crash`,
or `extendLost`. Any other process may extend any PCR at any time (R4). A
reboot, and a TPM reset or `TPM2_Clear` without one, start a TPM boot; a
TPM Restart or Resume does not, as `config_update_boot()` and
`check_record()` compare the reset count alone. The restart count, which
the read back of an extension compares, is left out: that check only
refuses more. Every state any sequence of these reaches from a fresh
target is `Reachable`.

Root decides when the TPM's boot changes and what a restart does: a
suspend to RAM at any point of a command is a TPM Resume, or a Restart,
which clears the PCRs, and `TPM2_Clear` sets the reset count back to
zero, so a later boot can have one an earlier one had. `rootTpm` is the
model with all of these. `journal_wellformed`, `mounted_selected`,
`boot_completion`, `completion_by_complete` and `extension_follows_save`
hold for it, and `pending_until_reboot` for every TPM. Every other theorem
is over `shirudo`, the same code on a calm TPM, whose reset count changes
only between commands, to one it never had, and which restarts without a
reboot only by a Resume between commands; `clear_in_flight_extends_twice`
breaks `extends_once` on root's TPM.

For every such sequence:

- (a) `consistent_or_refusing`: at every point the PCR replays from the
  record and the selected config is mounted, or `config_update_check()`
  refuses: a selection of this TPM boot pending, the PCR extended by
  another process, or no record of this TPM boot. `refusal_persists`: the
  first two last, with no command starting and shirudo extending nothing,
  until the TPM boot changes. `pending_until_reboot`: on any TPM, a
  pending activation stays pending through every resume and restart until
  the reset count changes.
- (b) `extends_once`: one extension per activation and TPM boot;
  `extension_follows_pending`: only with that activation's pending record
  saved; `interrupted_never_extends`: none after an interruption. On
  root's TPM, `extension_follows_save`: only for the record the command
  saved, durable as pending.
- (c) `reboot_stale`, `reboot_recovers`: after a reboot every command
  refuses until `init` records a boot event, and an `init` nothing
  interrupts does so, for the root `boot_target()` takes, and completes;
  `staged_taken`: that root is a staged one only when the stage copies
  the completed record `init` starts from and is of an earlier TPM boot,
  and `stage_then_reboot` gives a run that takes one;
  `boot_completion`: from any journal, `init` completes only with the
  PCR holding exactly the selected config's boot event over the value it
  started from.
- (d) `mounted_selected`, `consistent_mounted`: a command runs only with
  the config the record selects, and another one is mounted only while
  the selection is pending. `configInUse_vouched` restates `configInUse`;
  that it is what `current_config()` and `status_config()` give is by
  review.
- (e) `journal_wellformed`: no interruption leaves a journal a later boot
  refuses; `pcr_replay`: the PCR of a completed record holds its replay;
  `completion_by_complete`: a boot event is completed only by `init`'s
  `complete()`.

What the C relies on outside itself is part of the model, not an axiom:
commands run one at a time; a rename of `state` or `next-boot` is atomic
and survives a crash once made; a crash in an append leaves a prefix of
the line; only shirudo writes the config mount during a boot; for every
theorem over `Reachable`, only shirudo writes the journal, between boots
too, where R14 lets root rewrite it, while `boot_completion` and
`completion_by_complete` hold from any journal; a PCR changes only by
extension and resets only at a reboot or a TPM Restart; the model
compares PCRs as their lists of extensions, which
`pcr_value_eq_iff` justifies for the idealized hash of
`Shirudo.Chain.register_injective` and SHA-256 meets unless it collides
among the values compared; and, for the theorems over `shirudo`, the
calm TPM.

The variants `retry` and `recover` each add one step of code shirudo
does not have, and `retry_extends_twice` and `recover_admits_within_boot`
give a sequence for each that breaks the theorem it matches.
`clear_in_flight_extends_twice` is a sequence on root's TPM.
`resume_keeps_pending` is the trace a suspend to RAM gives: an
interrupted activation stays pending across it until a reboot.
-/

namespace Shirudo.ConfigActivation

/-! ### The journal and the PCR -/

/-- `enum config_event_kind`. -/
inductive Kind
  | boot
  | update
  deriving DecidableEq

/-- A line of `events`: the fields `same_event()` compares. `boot` is the
TPM's reset count, `initial` the `initial_pcr` the TPM
boot's boot event extended, as the extensions that value holds. -/
structure Event (B R D : Type) where
  seq : Nat
  boot : B
  pcr : Nat
  kind : Kind
  initial : List D
  root : R
  deriving DecidableEq

/-- The `state` file: the selection and whether it is pending. -/
structure Record (B R D : Type) where
  event : Event B R D
  pending : Bool
  deriving DecidableEq

section Model

variable {B R D : Type} [DecidableEq B] [DecidableEq R] [DecidableEq D]

/-- `event_follows()`: `none` is the zeroed record before the first line. -/
def Follows : Option (Event B R D) → Event B R D → Prop
  | none, e => e.seq = 1 ∧ e.kind = .boot
  | some p, e => e.seq = p.seq + 1 ∧
      (p.boot = e.boot → e.kind = .update ∧ p.pcr = e.pcr ∧
          p.initial = e.initial) ∧
      (p.boot ≠ e.boot → e.kind = .boot)

instance (p : Option (Event B R D)) (e : Event B R D) :
    Decidable (Follows p e) := by
  cases p <;> unfold Follows <;> infer_instance

variable (digest : Kind → R → D)

/-- One line of `events_scan()`: a boot event restarts from its
`initial_pcr`, then `chain_fold()` adds the line's
`config_measure_event()`. -/
def fold (e : Event B R D) (run : List D) : List D :=
  digest e.kind e.root :: (match e.kind with
    | .boot => e.initial
    | .update => run)

/-- `events_scan()` over the whole lines, the newest first: the last
event and the value they replay to, or `none` when a line does not
follow the one before it. -/
def scan : List (Event B R D) → Option (Option (Event B R D) × List D)
  | [] => some (none, [])
  | e :: es =>
    match scan es with
    | none => none
    | some (last, run) =>
      if Follows last e then some (some e, fold digest e run) else none

end Model

/-- What the C keeps across commands, and two ghosts. `state` and
`events` with `torn`, a partial last line, are the journal under
`/var/lib/shirudo/config-update`; `boot` the TPM's reset count; `pcr`
every PCR as its extensions this TPM boot, the newest
first; `mounted` the root of the config at `/run/shirudo/config`;
`cfgPcr` and `cfgImage` the runtime image's `config.pcr` and
`config.image`; `staged` the `next-boot` file of the journal, the record
`image stage` copied with the root it stages. The ghosts: `seen` every
TPM boot so far, and `sent` every extension of the config PCR shirudo
sent, with the TPM boot it was sent in and the sequence number of the
activation. -/
structure World (B R D : Type) where
  state : Option (Record B R D)
  events : List (Event B R D)
  torn : Bool
  boot : B
  pcr : Nat → List D
  mounted : Option R
  cfgPcr : Nat
  cfgImage : R
  staged : Option (Event B R D)
  seen : List B
  sent : List (B × Nat)

/-- Where the one command that holds the lock is, with what it keeps in
memory. The lock makes it one: every target command holds it for its
whole run. -/
inductive Proc (B R D : Type)
  | idle
  /-- `begin_event()` called, before `prepare` and `live_read()`. -/
  | starting (k : Kind) (t : R) (prev : Option (Event B R D))
  /-- The record built, before `state_save()`'s rename. -/
  | saving (e : Event B R D) (before : List D)
  | extending (e : Event B R D) (before : List D)
  | readback (e : Event B R D) (before : List D)
  | appending (e : Event B R D)
  | activating (e : Event B R D)
  /-- `init` after `image_boot()`, with `boot_pending` and the root it
  selected. -/
  | restOfInit (pending : Bool) (sel : R)
  /-- `complete()`, from `init` with the root it selected or from an
  update. -/
  | checking (sel : Option R)
  | marking (r : Event B R D) (sel : Option R)
  | marked (r : Event B R D) (sel : Option R)

structure Sys (B R D : Type) where
  w : World B R D
  proc : Proc B R D

/-- Models the code would be if it retried an extension whose answer was
lost or finished a pending activation within the TPM boot, and the TPM
it runs on: one whose resets, restarts and resumes can come in the middle
of a command, one that can come back to a reset count it had, and one
that restarts without a reboot, clearing the PCRs. -/
structure Variant where
  retry : Bool := false
  recover : Bool := false
  restartInFlight : Bool := false
  repeatBoot : Bool := false
  restartClears : Bool := false

/-- shirudo's code on a calm TPM, whose reset count changes only between
commands, to one it never had, and which restarts without a reboot only
by a Resume, between commands: the assumption every theorem over
`shirudo` carries. -/
def shirudo : Variant := {}

/-- shirudo's code on the TPM root drives. A suspend to RAM, at any point
of a command, is a TPM Resume, or a Restart, which clears the PCRs, and
`TPM2_Clear`, which only the lockout authorization that shirudo leaves
empty guards, sets the reset count back to zero, so a later TPM boot can
have one an earlier one had. -/
def rootTpm : Variant :=
  { restartInFlight := true, repeatBoot := true, restartClears := true }

/-- The result codes of `config_update_check()`. -/
inductive Res
  | ok
  | enoent
  | einprogress
  | euclean
  | enodata
  | estale
  deriving DecidableEq

section Model

variable {B R D : Type} [DecidableEq B] [DecidableEq R] [DecidableEq D]
variable (digest : Kind → R → D)

/-- `pcr_extend()`, `TPM2_PCR_Extend` of PCR `i` with a digest. -/
def extendAt (pcr : Nat → List D) (i : Nat) (d : D) : Nat → List D :=
  fun j => if j = i then d :: pcr j else pcr j

/-- `check_record()`: the journal replays, its last line is the record,
the TPM boot is the record's and the PCR holds the replayed value. -/
def checkRecord (w : World B R D) (r : Event B R D) : Res :=
  match scan digest w.events with
  | none => .euclean
  | some (last, exp) =>
    if w.torn then .enodata
    else if last ≠ some r then .euclean
    else if w.boot ≠ r.boot then .estale
    else if w.pcr r.pcr ≠ exp then .euclean
    else .ok

/-- `config_update_check()`. -/
def check (w : World B R D) : Res :=
  match w.state with
  | none => .enoent
  | some ⟨r, p⟩ => if p then .einprogress else checkRecord digest w r

/-- `current_config()`: what every target command but `status` and
`image status` needs before it runs, `config_update_check()` and
`config_mount_check()`. -/
def Admits (w : World B R D) : Prop :=
  check digest w = .ok ∧ ∃ r, w.state = some ⟨r, false⟩ ∧
    w.mounted = some r.root

/-- The config whose settings a command runs with: the consistent
record's, mounted, or for `status` the pending record's when it is the
one mounted (`status_config()`); none is the runtime image's alone. -/
def configInUse (w : World B R D) (status : Bool) : Option R :=
  match w.state with
  | none => none
  | some ⟨r, false⟩ =>
    if check digest w = .ok ∧ w.mounted = some r.root then some r.root else none
  | some ⟨r, true⟩ =>
    if status = true ∧ w.mounted = some r.root then some r.root else none

/-- The record `begin_event()` builds from what `live_read()` returns. -/
def newEvent (w : World B R D) (k : Kind) (t : R)
    (prev : Option (Event B R D)) : Event B R D where
  seq := (match prev with
    | none => 0
    | some p => p.seq) + 1
  boot := w.boot
  pcr := w.cfgPcr
  kind := k
  initial := match k, prev with
    | .boot, _ => w.pcr w.cfgPcr
    | .update, some p => p.initial
    | .update, none => []
  root := t

/-- `boot_target()` with `config_update_staged()`, for a record `r` of
another TPM boot: the staged root when the stage is not of this TPM boot,
names another root and has the record's sequence number and TPM boot,
the record's root otherwise. -/
def bootTarget (w : World B R D) (r : Event B R D) : R :=
  match w.staged with
  | some st =>
    if st.boot ≠ w.boot ∧ st.root ≠ r.root ∧ st.seq = r.seq ∧ st.boot = r.boot
    then st.root else r.root
  | none => r.root

/-- `complete_staged()` once `r` is complete: the stage stays only while
it is of `r`'s TPM boot. -/
def keepStaged (st : Option (Event B R D)) (r : Event B R D) :
    Option (Event B R D) :=
  match st with
  | some x => if x.boot = r.boot then some x else none
  | none => none

/-- The steps of one TPM boot. Every failure the C returns, and every
crash, is `crash`: what the C has written stays, nothing more is. -/
inductive StepIn (v : Variant) : Sys B R D → Sys B R D → Prop
  | crash (w : World B R D) (π : Proc B R D) : StepIn v ⟨w, π⟩ ⟨w, .idle⟩
  /-- Any other process extends any PCR (R4). -/
  | outsider (w : World B R D) (π : Proc B R D) (i : Nat) (d : D) :
      StepIn v ⟨w, π⟩ ⟨{ w with pcr := extendAt w.pcr i d }, π⟩
  /-- `image_update()`: `current_config()`, then `config_update_begin()`
  for another root on the same PCR. -/
  | startUpdate (w : World B R D) (t : R) (r : Event B R D) :
      w.state = some ⟨r, false⟩ → check digest w = .ok →
      w.mounted = some r.root → r.pcr = w.cfgPcr → t ≠ r.root →
      StepIn v ⟨w, .idle⟩ ⟨w, .starting .update t (some r)⟩
  /-- `image_boot()` when the record is of this TPM boot:
  `config_update_boot()` refuses a pending one, otherwise checks it. -/
  | initSame (w : World B R D) (r : Event B R D) :
      w.state = some ⟨r, false⟩ → r.boot = w.boot → r.pcr = w.cfgPcr →
      check digest w = .ok →
      StepIn v ⟨w, .idle⟩ ⟨w, .restOfInit false r.root⟩
  /-- `image_boot()` with no record: `boot_target()` takes `config.image`. -/
  | initFirst (w : World B R D) (x : List D) :
      w.state = none → scan digest w.events = some (none, x) →
      w.torn = false → StepIn v ⟨w, .idle⟩ ⟨w, .starting .boot w.cfgImage none⟩
  /-- `image_boot()` with a record of another TPM boot: the root
  `boot_target()` takes, the staged one or the record's, a journal that
  ends with the record or, pending, one it follows. -/
  | initNew (w : World B R D) (r : Event B R D) (q : Bool)
      (last : Option (Event B R D)) (x : List D) :
      w.state = some ⟨r, q⟩ → r.boot ≠ w.boot →
      scan digest w.events = some (last, x) → (w.torn = true → q = true) →
      (last = some r ∨ (q = true ∧ Follows last r)) →
      StepIn v ⟨w, .idle⟩ ⟨w, .starting .boot (bootTarget w r) last⟩
  /-- `image stage`: `current_config()`, then `config_update_stage()`
  saves the record with root `t` as `next-boot`, by a rename. -/
  | stage (w : World B R D) (t : R) (r : Event B R D) :
      w.state = some ⟨r, false⟩ → check digest w = .ok →
      w.mounted = some r.root →
      StepIn v ⟨w, .idle⟩
        ⟨{ w with staged := some { r with root := t } }, .idle⟩
  /-- `image stage --cancel`: `current_config()`, then the unlink of
  `next-boot`. -/
  | unstage (w : World B R D) (r : Event B R D) :
      w.state = some ⟨r, false⟩ → check digest w = .ok →
      w.mounted = some r.root →
      StepIn v ⟨w, .idle⟩ ⟨{ w with staged := none }, .idle⟩
  /-- `begin_event()`: `prepare`, `live_read()`, the record. -/
  | read (w : World B R D) (k : Kind) (t : R)
      (prev : Option (Event B R D)) :
      Follows prev (newEvent w k t prev) →
      StepIn v ⟨w, .starting k t prev⟩
        ⟨w, .saving (newEvent w k t prev) (w.pcr w.cfgPcr)⟩
  /-- `state_save()` of the pending record: the rename. -/
  | save (w : World B R D) (e : Event B R D) (b : List D) :
      StepIn v ⟨w, .saving e b⟩
        ⟨{ w with state := some ⟨e, true⟩ }, .extending e b⟩
  /-- `pcr_extend()` that the TPM applies. Its answer can still be lost:
  `crash` next is the ambiguous extension. -/
  | extend (w : World B R D) (e : Event B R D) (b : List D) :
      StepIn v ⟨w, .extending e b⟩
        ⟨{ w with
          pcr := extendAt w.pcr e.pcr (digest e.kind e.root),
          sent := (w.boot, e.seq) :: w.sent }, .readback e b⟩
  /-- `pcr_extend()` sent and not applied: an error. -/
  | extendLost (w : World B R D) (e : Event B R D) (b : List D) :
      StepIn v ⟨w, .extending e b⟩
        ⟨{ w with sent := (w.boot, e.seq) :: w.sent }, .idle⟩
  /-- `live_read()` after the extension: the record's TPM boot and the
  value expected. -/
  | readback (w : World B R D) (e : Event B R D) (b : List D) :
      w.boot = e.boot → w.pcr e.pcr = digest e.kind e.root :: b →
      StepIn v ⟨w, .readback e b⟩ ⟨w, .appending e⟩
  /-- `event_append()`: a boot event truncates a partial line, an update
  refuses one. -/
  | append (w : World B R D) (e : Event B R D) (last : Option (Event B R D))
      (x : List D) :
      (w.torn = true → e.kind = .boot) →
      scan digest w.events = some (last, x) → Follows last e →
      StepIn v ⟨w, .appending e⟩
        ⟨{ w with events := e :: w.events, torn := false }, .activating e⟩
  /-- A crash in the middle of the line. -/
  | appendTorn (w : World B R D) (e : Event B R D)
      (last : Option (Event B R D)) (x : List D) :
      (w.torn = true → e.kind = .boot) →
      scan digest w.events = some (last, x) → Follows last e →
      StepIn v ⟨w, .appending e⟩ ⟨{ w with torn := true }, .idle⟩
  /-- A failure after a boot event's `ftruncate()`. -/
  | appendTruncated (w : World B R D) (e : Event B R D)
      (last : Option (Event B R D)) (x : List D) :
      e.kind = .boot → scan digest w.events = some (last, x) →
      Follows last e →
      StepIn v ⟨w, .appending e⟩ ⟨{ w with torn := false }, .idle⟩
  /-- `activate`, `activate_config()`: the candidate mounted. -/
  | activateBoot (w : World B R D) (e : Event B R D) :
      e.kind = .boot →
      StepIn v ⟨w, .activating e⟩
        ⟨{ w with mounted := some e.root }, .restOfInit true e.root⟩
  | activateUpdate (w : World B R D) (e : Event B R D) :
      e.kind = .update →
      StepIn v ⟨w, .activating e⟩
        ⟨{ w with mounted := some e.root }, .checking none⟩
  /-- A failure after the old config was unmounted. -/
  | unmount (w : World B R D) (e : Event B R D) :
      StepIn v ⟨w, .activating e⟩ ⟨{ w with mounted := none }, .idle⟩
  /-- `image_boot_complete()` once the restore and the register binding
  succeeded: `config_mount_check()`, then `complete()`. -/
  | initComplete (w : World B R D) (sel : R) (r : Event B R D) (q : Bool) :
      w.state = some ⟨r, q⟩ → w.mounted = some r.root →
      StepIn v ⟨w, .restOfInit true sel⟩ ⟨w, .checking (some sel)⟩
  /-- The same without `boot_pending`: `config_update_check()`, then
  `complete_staged()`. -/
  | initDone (w : World B R D) (sel : R) (r : Event B R D) (q : Bool) :
      w.state = some ⟨r, q⟩ → w.mounted = some r.root →
      check digest w = .ok →
      StepIn v ⟨w, .restOfInit false sel⟩
        ⟨{ w with staged := keepStaged w.staged r }, .idle⟩
  /-- `complete()`: `check_record()` of the record, pending or not. -/
  | check (w : World B R D) (sel : Option R) (r : Event B R D) (q : Bool) :
      w.state = some ⟨r, q⟩ → checkRecord digest w r = .ok →
      StepIn v ⟨w, .checking sel⟩ ⟨w, .marking r sel⟩
  /-- `complete()`'s `state_save()`: the rename. -/
  | mark (w : World B R D) (r : Event B R D) (sel : Option R) :
      StepIn v ⟨w, .marking r sel⟩
        ⟨{ w with state := some ⟨r, false⟩ }, .marked r sel⟩
  /-- A failure after that rename: the pending record restored. -/
  | restore (w : World B R D) (r : Event B R D) (sel : Option R) :
      StepIn v ⟨w, .marked r sel⟩ ⟨{ w with state := some ⟨r, true⟩ }, .idle⟩
  /-- `complete()` done: `config_update_begin()` removes `next-boot` after
  an update, `complete_staged()` after `init`'s boot event unless it is
  of the record's TPM boot. -/
  | clearStaged (w : World B R D) (r : Event B R D) (sel : Option R) :
      StepIn v ⟨w, .marked r sel⟩
        ⟨{ w with staged := match sel with
          | none => none
          | some _ => keepStaged w.staged r }, .idle⟩
  /-- Variant: an extension whose answer was lost, applied or not, sent
  again. -/
  | retry (w : World B R D) (e : Event B R D) (b : List D) (applied : Bool) :
      v.retry = true →
      StepIn v ⟨w, .extending e b⟩
        ⟨{ w with
          pcr := if applied then extendAt w.pcr e.pcr (digest e.kind e.root)
            else w.pcr,
          sent := (w.boot, e.seq) :: w.sent }, .extending e b⟩
  /-- Variant: a command that finds a pending activation of this TPM boot
  in the PCR and records it complete. -/
  | recover (w : World B R D) (r : Event B R D) :
      v.recover = true → w.state = some ⟨r, true⟩ → r.boot = w.boot →
      checkRecord digest w r = .ok →
      StepIn v ⟨w, .idle⟩ ⟨{ w with state := some ⟨r, false⟩ }, .idle⟩

/-- A step: one within the TPM boot, a reboot, a TPM reset or
`TPM2_Clear` without one, or a TPM Restart or Resume. The TPM boot is the
reset count. A reboot and a reset give it a value it never had, unless
`repeatBoot` lets a `TPM2_Clear` bring back an old one; a Restart or a
Resume keeps it. A reboot ends the command, empties `/run` and leaves the
PCRs with what the firmware extended; it may bring a new runtime image.
Otherwise the OS and its mounts run on: a reset or a Restart clears the
PCRs, a `TPM2_Clear` or a Resume keeps them (`keep`). -/
inductive Step (v : Variant) : Sys B R D → Sys B R D → Prop
  | inBoot {s s' : Sys B R D} : StepIn digest v s s' → Step v s s'
  | reboot (s : Sys B R D) (b : B) (f : Nat → List D) (idx : Nat) (img : R) :
      (b ∉ s.w.seen ∨ v.repeatBoot = true) →
      Step v s ⟨{ s.w with
        boot := b, pcr := f, mounted := none, cfgPcr := idx, cfgImage := img,
        seen := b :: s.w.seen }, .idle⟩
  | reset (s : Sys B R D) (b : B) (keep : Bool) (f : Nat → List D) :
      (s.proc = .idle ∨ v.restartInFlight = true) →
      (b ∉ s.w.seen ∨ v.repeatBoot = true) →
      Step v s ⟨{ s.w with
        boot := b, pcr := if keep then s.w.pcr else f,
        seen := b :: s.w.seen }, s.proc⟩
  | restart (s : Sys B R D) (keep : Bool) (f : Nat → List D) :
      (s.proc = .idle ∨ v.restartInFlight = true) →
      (keep = true ∨ v.restartClears = true) →
      Step v s ⟨{ s.w with pcr := if keep then s.w.pcr else f }, s.proc⟩

/-- A step that keeps the TPM's reset count: one within the TPM boot, or a
TPM Restart or Resume. -/
inductive SameBoot (v : Variant) : Sys B R D → Sys B R D → Prop
  | inBoot {s s' : Sys B R D} : StepIn digest v s s' → SameBoot v s s'
  | restart (s : Sys B R D) (keep : Bool) (f : Nat → List D) :
      (s.proc = .idle ∨ v.restartInFlight = true) →
      (keep = true ∨ v.restartClears = true) →
      SameBoot v s ⟨{ s.w with pcr := if keep then s.w.pcr else f }, s.proc⟩

/-- The reflexive and transitive closure of a relation. -/
inductive Star {α : Type} (r : α → α → Prop) : α → α → Prop
  | refl (a : α) : Star r a a
  | tail {a b c : α} : Star r a b → r b c → Star r a c

/-- A target before its first `init`: no journal, nothing mounted. -/
def fresh (b : B) (f : Nat → List D) (idx : Nat) (img : R) : World B R D where
  state := none
  events := []
  torn := false
  boot := b
  pcr := f
  mounted := none
  cfgPcr := idx
  cfgImage := img
  staged := none
  seen := [b]
  sent := []

/-- Every state some sequence of commands, interruptions and boots
reaches from a fresh target. -/
def Reachable (v : Variant) (s : Sys B R D) : Prop :=
  ∃ b f idx img, Star (Step digest v) ⟨fresh b f idx img, .idle⟩ s

/-! ### Invariants -/

/-- What the world keeps true in every reachable state. -/
structure Glob (w : World B R D) : Prop where
  /-- Every line follows the one before; a torn line or a record ahead
  of the journal only while a selection is pending. -/
  journal : ∃ last x, scan digest w.events = some (last, x) ∧
    (w.state = none → w.events = [] ∧ w.torn = false) ∧
    (∀ r, w.state = some ⟨r, false⟩ → last = some r ∧ w.torn = false) ∧
    (∀ r, w.state = some ⟨r, true⟩ → last = some r ∨ Follows last r)
  boot_seen : w.boot ∈ w.seen
  state_seen : ∀ r q, w.state = some ⟨r, q⟩ → r.boot ∈ w.seen
  events_seen : ∀ e ∈ w.events, e.boot ∈ w.seen
  sent_seen : ∀ p ∈ w.sent, p.1 ∈ w.seen
  sent_nodup : w.sent.Nodup
  /-- An extension of this TPM boot is of the record's activation or an
  earlier one. -/
  sent_state : ∀ n, (w.boot, n) ∈ w.sent →
    ∃ r q, w.state = some ⟨r, q⟩ ∧ r.boot = w.boot ∧ n ≤ r.seq
  /-- A completed record of this TPM boot: the PCR holds its replay,
  perhaps with other extensions on top. -/
  suffix : ∀ r x, w.state = some ⟨r, false⟩ → r.boot = w.boot →
    scan digest w.events = some (some r, x) → ∃ xs, w.pcr r.pcr = xs ++ x
  mounted_state : ∀ m, w.mounted = some m →
    ∃ r q, w.state = some ⟨r, q⟩ ∧ (m = r.root ∨ q = true)
  state_mounted : ∀ r, w.state = some ⟨r, false⟩ → r.boot = w.boot →
    w.mounted = some r.root

/-- What the command in progress has made true, from any journal. -/
def Base (w : World B R D) : Proc B R D → Prop
  | .idle => True
  | .starting .update _ prev =>
    ∃ r, prev = some r ∧ w.state = some ⟨r, false⟩ ∧ r.boot = w.boot
  | .starting .boot _ _ => True
  | .saving e _ => e.boot = w.boot
  | .extending e _ => w.state = some ⟨e, true⟩ ∧ e.boot = w.boot
  | .readback e _ => w.state = some ⟨e, true⟩ ∧ e.boot = w.boot
  | .appending e => w.state = some ⟨e, true⟩ ∧ e.boot = w.boot
  | .activating e => w.state = some ⟨e, true⟩ ∧ e.boot = w.boot
  | .restOfInit true sel => ∃ e, w.state = some ⟨e, true⟩ ∧ e.boot = w.boot ∧
      e.kind = .boot ∧ e.root = sel ∧ w.mounted = some sel
  | .restOfInit false _ => True
  | .checking sel => ∃ e, w.state = some ⟨e, true⟩ ∧ e.boot = w.boot ∧
      w.mounted = some e.root ∧
      (∀ s, sel = some s → e.kind = .boot ∧ e.root = s) ∧
      (sel = none → e.kind = .update)
  | .marking r sel => w.state = some ⟨r, true⟩ ∧ r.boot = w.boot ∧
      w.mounted = some r.root ∧
      (∀ s, sel = some s → r.kind = .boot ∧ r.root = s) ∧
      (sel = none → r.kind = .update) ∧
      ∃ x, scan digest w.events = some (some r, x) ∧ w.torn = false ∧
        ∃ xs, w.pcr r.pcr = xs ++ x
  | .marked r sel => w.state = some ⟨r, false⟩ ∧ r.boot = w.boot ∧
      w.mounted = some r.root ∧
      (∀ s, sel = some s → r.kind = .boot ∧ r.root = s) ∧
      (sel = none → r.kind = .update)

/-- What the command in progress needs of a journal shirudo wrote. -/
def Ext (w : World B R D) : Proc B R D → Prop
  | .starting .boot _ prev => (∃ x, scan digest w.events = some (prev, x)) ∧
      ∀ r q, w.state = some ⟨r, q⟩ → r.boot ≠ w.boot
  | .saving e _ =>
      (∃ last x, scan digest w.events = some (last, x) ∧ Follows last e) ∧
      ∀ n, (w.boot, n) ∈ w.sent → n < e.seq
  | .extending e _ => ∀ n, (w.boot, n) ∈ w.sent → n < e.seq
  | _ => True

/-- The world a reboot leaves: a TPM boot it never had, the PCRs the
firmware extended, nothing mounted, perhaps a new runtime image. -/
def afterReboot (w : World B R D) (b : B) (f : Nat → List D) (idx : Nat)
    (img : R) : World B R D :=
  { w with
    boot := b, pcr := f, mounted := none, cfgPcr := idx, cfgImage := img,
    seen := b :: w.seen }

/-- `boot_target()`: without a record `config.image`; with one, pending
or not, the staged root `bootTarget` takes or the record's. -/
def selected (w : World B R D) : R :=
  match w.state with
  | none => w.cfgImage
  | some ⟨r, _⟩ => bootTarget w r

/-- `init` has not recorded this TPM boot: no record, or one of another
TPM boot. `config_update_check()` refuses with `ENOENT` or `ESTALE`. -/
def Stale (w : World B R D) : Prop :=
  ∀ r q, w.state = some ⟨r, q⟩ → r.boot ≠ w.boot

/-- A selection of this TPM boot is pending: `EINPROGRESS`. -/
def PendingHere (w : World B R D) : Prop :=
  ∃ r, w.state = some ⟨r, true⟩ ∧ r.boot = w.boot

/-- A completed selection of this TPM boot whose PCR something else
extended since: `EUCLEAN`. -/
def Drift (w : World B R D) : Prop :=
  ∃ r x xs, w.state = some ⟨r, false⟩ ∧ r.boot = w.boot ∧
    scan digest w.events = some (some r, x) ∧ w.torn = false ∧ xs ≠ [] ∧
    w.pcr r.pcr = xs ++ x

/-- The invariant. -/
def Inv (s : Sys B R D) : Prop :=
  Glob digest s.w ∧ Base digest s.w s.proc ∧ Ext digest s.w s.proc

end Model

/-! ### Lemmas -/

section PCR

variable {D : Type}

theorem extendAt_self (pcr : Nat → List D) (i : Nat) (d : D) :
    extendAt pcr i d i = d :: pcr i := by
  simp [extendAt]

/-- Another extension keeps a PCR an extension of what it was. -/
theorem extendAt_suffix (pcr : Nat → List D) (i j : Nat) (d : D) (x : List D)
    (h : ∃ xs, pcr j = xs ++ x) : ∃ xs, extendAt pcr i d j = xs ++ x := by
  obtain ⟨xs, hx⟩ := h
  by_cases hj : j = i
  · exact ⟨d :: xs, by simp [extendAt, hj] at hx ⊢; simp [hx]⟩
  · exact ⟨xs, by simp [extendAt, hj, hx]⟩

/-- The C compares PCR values, which `Shirudo.Chain.register` gives of the
model's lists of extensions; for a hash injective on every pair, as
`Shirudo.Chain.register_injective` takes it, two values are equal exactly
when the lists are, so comparing lists is comparing values. No hash onto
32 bytes is that; SHA-256 is unless it collides among the values the C
compares. -/
theorem pcr_value_eq_iff {H : D → D → D} {init : D}
    (hH : ∀ a b c d, H a b = H c d → a = c ∧ b = d)
    (hinit : ∀ a b, H a b ≠ init) (l1 l2 : List D) :
    Chain.register H init l1 = Chain.register H init l2 ↔ l1 = l2 :=
  ⟨Chain.register_injective H init hH hinit l1 l2, fun h => h ▸ rfl⟩

/-- `extendAt` is `chain_fold()` on the value. -/
theorem register_extendAt (H : D → D → D) (init : D) (pcr : Nat → List D)
    (i : Nat) (d : D) :
    Chain.register H init (extendAt pcr i d i) =
      H (Chain.register H init (pcr i)) d := by
  simp [extendAt, Chain.register]

end PCR

section Lemmas

variable {B R D : Type} [DecidableEq B] [DecidableEq R] [DecidableEq D]
variable {digest : Kind → R → D}

omit [DecidableEq R] in
theorem scan_cons {e : Event B R D} {es : List (Event B R D)}
    {p : Option (Event B R D) × List D} :
    scan digest (e :: es) = some p ↔
      ∃ last run, scan digest es = some (last, run) ∧ Follows last e ∧
        p = (some e, fold digest e run) := by
  simp only [scan]
  cases h : scan digest es with
  | none => simp
  | some q =>
    obtain ⟨last, run⟩ := q
    by_cases hf : Follows last e
    · simp only [hf, ite_true, Option.some.injEq]
      constructor
      · rintro rfl
        exact ⟨last, run, rfl, hf, rfl⟩
      · rintro ⟨l, r', hlr, -, rfl⟩
        cases hlr
        rfl
    · simp only [hf, ite_false, reduceCtorEq, false_iff]
      rintro ⟨l, r', hlr, hf', -⟩
      cases hlr
      exact hf hf'

theorem checkRecord_ok {w : World B R D} {r : Event B R D} :
    checkRecord digest w r = .ok ↔
      ∃ x, scan digest w.events = some (some r, x) ∧ w.torn = false ∧
        w.boot = r.boot ∧ w.pcr r.pcr = x := by
  unfold checkRecord
  cases h : scan digest w.events with
  | none => simp
  | some q =>
    obtain ⟨last, exp⟩ := q
    by_cases ht : w.torn = true <;> by_cases hl : last = some r <;>
      by_cases hb : w.boot = r.boot <;> by_cases hp : w.pcr r.pcr = exp <;>
      simp_all

theorem check_ok {w : World B R D} :
    check digest w = .ok ↔ ∃ r, w.state = some ⟨r, false⟩ ∧
      checkRecord digest w r = .ok := by
  unfold check
  cases h : w.state with
  | none => simp
  | some q =>
    obtain ⟨r, p⟩ := q
    cases p <;> simp

end Lemmas

/-! ### The command in progress -/

section Base

variable {B R D : Type} [DecidableEq B] [DecidableEq D]
variable {digest : Kind → R → D}

theorem base_outsider {w : World B R D} {π : Proc B R D} (i : Nat) (d : D)
    (hb : Base digest w π) :
    Base digest { w with pcr := extendAt w.pcr i d } π := by
  cases π with
  | idle => trivial
  | starting k t prev => cases k <;> exact hb
  | saving e b => exact hb
  | extending e b => exact hb
  | readback e b => exact hb
  | appending e => exact hb
  | activating e => exact hb
  | restOfInit p sel => cases p <;> exact hb
  | checking sel => exact hb
  | marking r sel =>
    obtain ⟨h1, h2, h3, h4, h4', x, h5, h6, h7⟩ := hb
    exact ⟨h1, h2, h3, h4, h4', x, h5, h6, extendAt_suffix _ _ _ _ _ h7⟩
  | marked r sel => exact hb

/-- The command's facts hold from any journal, under any interruption. -/
theorem base_stepIn [DecidableEq R] {s s' : Sys B R D}
    (hb : Base digest s.w s.proc)
    (h : StepIn digest shirudo s s') : Base digest s'.w s'.proc := by
  cases h with
  | crash => trivial
  | outsider w π i d => exact base_outsider i d hb
  | startUpdate w t r hs hc _ _ _ =>
    obtain ⟨x, -, -, hboot, -⟩ := checkRecord_ok.1 (by
      obtain ⟨r', hs', hr'⟩ := check_ok.1 hc
      rw [hs] at hs'
      cases hs'
      exact hr')
    exact ⟨r, rfl, hs, hboot.symm⟩
  | initSame => trivial
  | initFirst => trivial
  | initNew => trivial
  | read w k t prev _ => rfl
  | save w e b => exact ⟨rfl, hb⟩
  | extend w e b => exact hb
  | extendLost => trivial
  | readback w e b _ _ => exact hb
  | append w e last x _ _ _ => exact hb
  | appendTorn => trivial
  | appendTruncated => trivial
  | activateBoot w e hk => exact ⟨e, hb.1, hb.2, hk, rfl, rfl⟩
  | activateUpdate w e hk =>
    exact ⟨e, hb.1, hb.2, rfl, (fun _ h => by cases h), fun _ => hk⟩
  | unmount => trivial
  | initComplete w sel r q _ _ =>
    obtain ⟨e, h1, h2, h3, h4, h5⟩ := hb
    refine ⟨e, h1, h2, by rw [h5, h4], ?_, fun h => by cases h⟩
    intro s hs
    cases hs
    exact ⟨h3, h4⟩
  | initDone => trivial
  | check w sel r q hs hc =>
    obtain ⟨e, h1, h2, h3, h4, h4'⟩ := hb
    rw [h1] at hs
    cases hs
    obtain ⟨x, hx, ht, -, hp⟩ := checkRecord_ok.1 hc
    exact ⟨h1, h2, h3, h4, h4', x, hx, ht, [], by simp [hp]⟩
  | mark w r sel =>
    obtain ⟨-, h2, h3, h4, h4', -⟩ := hb
    exact ⟨rfl, h2, h3, h4, h4'⟩
  | restore => trivial
  | stage => trivial
  | unstage => trivial
  | clearStaged => trivial
  | retry _ _ _ _ hv => simp [shirudo] at hv
  | recover _ _ hv => simp [shirudo] at hv

/-- Reboots and TPM restarts keep the facts too: a reboot ends the
command, and a restart comes only between commands. -/
theorem base_step [DecidableEq R] {s s' : Sys B R D}
    (hb : Base digest s.w s.proc)
    (h : Step digest shirudo s s') : Base digest s'.w s'.proc := by
  cases h with
  | inBoot h => exact base_stepIn hb h
  | reboot => trivial
  | reset b keep f hidle _ =>
    rcases hidle with hidle | hidle
    · simp only [hidle]
      trivial
    · simp [shirudo] at hidle
  | restart keep f hidle _ =>
    rcases hidle with hidle | hidle
    · simp only [hidle]
      trivial
    · simp [shirudo] at hidle

theorem base_star [DecidableEq R] {s s' : Sys B R D}
    (hb : Base digest s.w s.proc)
    (h : Star (Step digest shirudo) s s') : Base digest s'.w s'.proc := by
  induction h with
  | refl => exact hb
  | tail _ hstep ih => exact base_step ih hstep

end Base

/-! ### The world -/

section Glob

variable {B R D : Type} [DecidableEq B] [DecidableEq D]
variable {digest : Kind → R → D}

theorem glob_outsider {w : World B R D} (i : Nat) (d : D) (hg : Glob digest w) :
    Glob digest { w with pcr := extendAt w.pcr i d } :=
  ⟨hg.journal, hg.boot_seen, hg.state_seen, hg.events_seen, hg.sent_seen,
    hg.sent_nodup,
    hg.sent_state,
    fun r x hs hb hx => extendAt_suffix _ _ _ _ _ (hg.suffix r x hs hb hx),
    hg.mounted_state, hg.state_mounted⟩

/-- `next-boot` written or removed: nothing else changes. -/
theorem glob_staged {w : World B R D} (st : Option (Event B R D))
    (hg : Glob digest w) : Glob digest { w with staged := st } :=
  ⟨hg.journal, hg.boot_seen, hg.state_seen, hg.events_seen, hg.sent_seen,
    hg.sent_nodup, hg.sent_state, hg.suffix, hg.mounted_state,
    hg.state_mounted⟩

/-- `state_save()` of the pending record. -/
theorem glob_save {w : World B R D} {e : Event B R D} (hg : Glob digest w)
    (hb : e.boot = w.boot)
    (hf : ∃ last x, scan digest w.events = some (last, x) ∧ Follows last e)
    (hlt : ∀ n, (w.boot, n) ∈ w.sent → n < e.seq) :
    Glob digest { w with state := some ⟨e, true⟩ } := by
  obtain ⟨last, x, hscan, hf⟩ := hf
  refine ⟨⟨last, x, hscan, (fun h => by cases h), (fun r h => by cases h), ?_⟩,
    hg.boot_seen, ?_, hg.events_seen, hg.sent_seen, hg.sent_nodup, ?_,
    (fun r x h => by cases h), fun _ _ => ⟨e, true, rfl, Or.inr rfl⟩,
    (fun r h => by cases h)⟩
  · intro r h
    cases h
    exact Or.inr hf
  · intro r q h
    cases h
    show e.boot ∈ w.seen
    rw [hb]
    exact hg.boot_seen
  · intro n hn
    exact ⟨e, true, rfl, hb, Nat.le_of_lt (hlt n hn)⟩

/-- `pcr_extend()`, applied or not, with the pending record saved. -/
theorem glob_sent {w : World B R D} {e : Event B R D} (pcr : Nat → List D)
    (hg : Glob digest w) (hs : w.state = some ⟨e, true⟩) (hb : e.boot = w.boot)
    (hlt : ∀ n, (w.boot, n) ∈ w.sent → n < e.seq) :
    Glob digest { w with pcr := pcr, sent := (w.boot, e.seq) :: w.sent } := by
  refine ⟨hg.journal, hg.boot_seen, hg.state_seen, hg.events_seen, ?_, ?_, ?_,
    (fun r x h => by rw [hs] at h; cases h), hg.mounted_state,
    (fun r h => by rw [hs] at h; cases h)⟩
  · intro p hp
    rcases List.mem_cons.1 hp with hp | hp
    · rw [hp]
      exact hg.boot_seen
    · exact hg.sent_seen p hp
  · exact List.nodup_cons.2
      ⟨fun hm => Nat.lt_irrefl _ (hlt _ hm), hg.sent_nodup⟩
  · intro n hn
    rcases List.mem_cons.1 hn with hn | hn
    · cases hn
      exact ⟨e, true, hs, hb, Nat.le_refl _⟩
    · exact hg.sent_state n hn

/-- `event_append()` of the whole line. -/
theorem glob_append {w : World B R D} {e : Event B R D}
    {last : Option (Event B R D)} {x : List D} (hg : Glob digest w)
    (hs : w.state = some ⟨e, true⟩) (hb : e.boot = w.boot)
    (hscan : scan digest w.events = some (last, x)) (hf : Follows last e) :
    Glob digest { w with events := e :: w.events, torn := false } := by
  refine ⟨⟨some e, fold digest e x, scan_cons.2 ⟨last, x, hscan, hf, rfl⟩,
      (fun h => by rw [hs] at h; cases h),
        (fun r h => by rw [hs] at h; cases h),
      (fun r h => by rw [hs] at h; cases h; exact Or.inl rfl)⟩,
    hg.boot_seen, hg.state_seen, ?_, hg.sent_seen, hg.sent_nodup, hg.sent_state,
    (fun r x h => by rw [hs] at h; cases h), hg.mounted_state,
    (fun r h => by rw [hs] at h; cases h)⟩
  intro e' he'
  rcases List.mem_cons.1 he' with he' | he'
  · rw [he']
    show e.boot ∈ w.seen
    rw [hb]
    exact hg.boot_seen
  · exact hg.events_seen e' he'

/-- A partial line written, or one truncated, while the record is
pending. -/
theorem glob_torn {w : World B R D} {e : Event B R D} (t : Bool)
    (hg : Glob digest w) (hs : w.state = some ⟨e, true⟩) :
    Glob digest { w with torn := t } := by
  obtain ⟨last, x, hscan, -, -, hp⟩ := hg.journal
  exact ⟨⟨last, x, hscan, (fun h => by rw [hs] at h; cases h),
      (fun r h => by rw [hs] at h; cases h), hp⟩,
    hg.boot_seen, hg.state_seen, hg.events_seen, hg.sent_seen, hg.sent_nodup,
    hg.sent_state, (fun r x h => by rw [hs] at h; cases h), hg.mounted_state,
    (fun r h => by rw [hs] at h; cases h)⟩

/-- A mount or an unmount while the record is pending. -/
theorem glob_mount {w : World B R D} {e : Event B R D} (m : Option R)
    (hg : Glob digest w) (hs : w.state = some ⟨e, true⟩) :
    Glob digest { w with mounted := m } :=
  ⟨hg.journal, hg.boot_seen, hg.state_seen, hg.events_seen, hg.sent_seen,
    hg.sent_nodup,
    hg.sent_state, hg.suffix, fun _ _ => ⟨e, true, hs, Or.inr rfl⟩,
    (fun r h => by rw [hs] at h; cases h)⟩

/-- `complete()`'s `state_save()` after its `check_record()`. -/
theorem glob_mark {w : World B R D} {r : Event B R D} {sel : Option R}
    (hg : Glob digest w) (hb : Base digest w (.marking r sel)) :
    Glob digest { w with state := some ⟨r, false⟩ } := by
  obtain ⟨hs, -, hm, -, -, x, hx, ht, xs, hp⟩ := hb
  refine ⟨⟨some r, x, hx, (fun h => by cases h),
      (fun r' h => by cases h; exact ⟨rfl, ht⟩),
      (fun r' h => by cases h)⟩,
    hg.boot_seen, ?_, hg.events_seen, hg.sent_seen, hg.sent_nodup, ?_, ?_, ?_,
      ?_⟩
  · intro r' q h
    cases h
    exact hg.state_seen r true hs
  · intro n hn
    obtain ⟨r', q', hs', hb', hle⟩ := hg.sent_state n hn
    rw [hs] at hs'
    cases hs'
    exact ⟨r, false, rfl, hb', hle⟩
  · intro r' x' h _ hx'
    cases h
    rw [hx] at hx'
    cases hx'
    exact ⟨xs, hp⟩
  · intro m h
    rw [hm] at h
    cases h
    exact ⟨r, false, rfl, Or.inl rfl⟩
  · intro r' h _
    cases h
    exact hm

/-- `complete()` restoring the pending record. -/
theorem glob_restore {w : World B R D} {r : Event B R D} (hg : Glob digest w)
    (hs : w.state = some ⟨r, false⟩) :
    Glob digest { w with state := some ⟨r, true⟩ } := by
  obtain ⟨last, x, hscan, -, hnp, -⟩ := hg.journal
  refine ⟨⟨last, x, hscan, (fun h => by cases h), (fun r' h => by cases h),
      (fun r' h => by cases h; exact Or.inl (hnp r hs).1)⟩,
    hg.boot_seen, ?_, hg.events_seen, hg.sent_seen, hg.sent_nodup, ?_,
    (fun r' x h => by cases h), fun _ _ => ⟨r, true, rfl, Or.inr rfl⟩,
    (fun r' h => by cases h)⟩
  · intro r' q h
    cases h
    exact hg.state_seen r false hs
  · intro n hn
    obtain ⟨r', q', hs', hb', hle⟩ := hg.sent_state n hn
    rw [hs] at hs'
    cases hs'
    exact ⟨r, true, rfl, hb', hle⟩

/-- A new TPM boot: nothing of the journal or the ghosts is of it. -/
theorem glob_newBoot {w : World B R D} {b : B} (pcr : Nat → List D)
    (m : Option R) (idx : Nat) (img : R) (hg : Glob digest w)
    (hnew : b ∉ w.seen) (hm : m = none ∨ m = w.mounted) :
    Glob digest { w with
      boot := b, pcr := pcr, mounted := m, cfgPcr := idx, cfgImage := img,
      seen := b :: w.seen } := by
  refine ⟨hg.journal, List.mem_cons_self,
    fun r q h => List.mem_cons_of_mem _ (hg.state_seen r q h),
    fun e he => List.mem_cons_of_mem _ (hg.events_seen e he),
    fun p hp => List.mem_cons_of_mem _ (hg.sent_seen p hp), hg.sent_nodup,
    fun n hn => absurd (hg.sent_seen _ hn) hnew, ?_, ?_, ?_⟩
  · intro r x h hrb _
    have hr := hg.state_seen r false h
    rw [show r.boot = b from hrb] at hr
    exact absurd hr hnew
  · intro m' h
    rcases hm with hm | hm
    · rw [hm] at h
      cases h
    · rw [hm] at h
      exact hg.mounted_state m' h
  · intro r h hrb
    have hr := hg.state_seen r false h
    rw [show r.boot = b from hrb] at hr
    exact absurd hr hnew

end Glob

/-! ### The invariant holds in every reachable state -/

section Inv

variable {B R D : Type} [DecidableEq B] [DecidableEq R] [DecidableEq D]
variable {digest : Kind → R → D}

omit [DecidableEq R] in
theorem ext_outsider {w : World B R D} {π : Proc B R D} (i : Nat) (d : D)
    (he : Ext digest w π) :
    Ext digest { w with pcr := extendAt w.pcr i d } π := by
  cases π with
  | starting k t prev => cases k <;> exact he
  | saving e b => exact he
  | extending e b => exact he
  | idle => trivial
  | readback => trivial
  | appending => trivial
  | activating => trivial
  | restOfInit => trivial
  | checking => trivial
  | marking => trivial
  | marked => trivial

theorem inv_stepIn {s s' : Sys B R D} (hi : Inv digest s)
    (h : StepIn digest shirudo s s') :
    Inv digest s' := by
  obtain ⟨hg, hb, he⟩ := hi
  refine ⟨?_, base_stepIn hb h, ?_⟩
  · cases h with
    | crash => exact hg
    | outsider w π i d => exact glob_outsider i d hg
    | startUpdate => exact hg
    | initSame => exact hg
    | initFirst => exact hg
    | initNew => exact hg
    | read => exact hg
    | save w e b => exact glob_save hg hb he.1 he.2
    | extend w e b => exact glob_sent _ hg hb.1 hb.2 he
    | extendLost w e b => exact glob_sent w.pcr hg hb.1 hb.2 he
    | readback => exact hg
    | append w e last x _ hscan hf => exact glob_append hg hb.1 hb.2 hscan hf
    | appendTorn w e => exact glob_torn true hg hb.1
    | appendTruncated w e => exact glob_torn false hg hb.1
    | activateBoot w e => exact glob_mount _ hg hb.1
    | activateUpdate w e => exact glob_mount _ hg hb.1
    | unmount w e => exact glob_mount _ hg hb.1
    | initComplete => exact hg
    | initDone => exact glob_staged _ hg
    | check => exact hg
    | mark w r sel => exact glob_mark hg hb
    | restore w r sel => exact glob_restore hg hb.1
    | stage => exact glob_staged _ hg
    | unstage => exact glob_staged _ hg
    | clearStaged => exact glob_staged _ hg
    | retry _ _ _ _ hv => simp [shirudo] at hv
    | recover _ _ hv => simp [shirudo] at hv
  · cases h with
    | crash => trivial
    | outsider w π i d => exact ext_outsider i d he
    | startUpdate => trivial
    | initSame => trivial
    | initFirst w x hs hscan _ =>
      exact ⟨⟨x, hscan⟩, fun r q h => by rw [hs] at h; cases h⟩
    | initNew w r q last x hs hrb hscan _ _ =>
      refine ⟨⟨x, hscan⟩, fun r' q' h => ?_⟩
      rw [hs] at h
      cases h
      exact hrb
    | read w k t prev hf =>
      cases k with
      | boot =>
        obtain ⟨⟨x, hx⟩, hother⟩ := he
        refine ⟨⟨prev, x, hx, hf⟩, fun n hn => ?_⟩
        obtain ⟨r, q, hs, hrb, -⟩ := hg.sent_state n hn
        exact absurd hrb (hother r q hs)
      | update =>
        obtain ⟨r, hprev, hs, -⟩ := hb
        subst hprev
        obtain ⟨last, x, hscan, -, hnp, -⟩ := hg.journal
        obtain ⟨hlast, -⟩ := hnp r hs
        subst hlast
        refine ⟨⟨some r, x, hscan, hf⟩, fun n hn => ?_⟩
        obtain ⟨r', q', hs', -, hle⟩ := hg.sent_state n hn
        rw [hs] at hs'
        cases hs'
        show n < r.seq + 1
        omega
    | save w e b => exact he.2
    | extend => trivial
    | extendLost => trivial
    | readback => trivial
    | append => trivial
    | appendTorn => trivial
    | appendTruncated => trivial
    | activateBoot => trivial
    | activateUpdate => trivial
    | unmount => trivial
    | initComplete => trivial
    | initDone => trivial
    | check => trivial
    | mark => trivial
    | restore => trivial
    | stage => trivial
    | unstage => trivial
    | clearStaged => trivial
    | retry _ _ _ _ hv => simp [shirudo] at hv
    | recover _ _ hv => simp [shirudo] at hv

theorem inv_step {s s' : Sys B R D} (hi : Inv digest s)
    (h : Step digest shirudo s s') :
    Inv digest s' := by
  cases h with
  | inBoot h => exact inv_stepIn hi h
  | reboot b f idx img hnew =>
    rcases hnew with hnew | hnew
    · exact ⟨glob_newBoot f none idx img hi.1 hnew (Or.inl rfl), trivial,
        trivial⟩
    · simp [shirudo] at hnew
  | reset b keep f hidle hnew =>
    have hnew : b ∉ s.w.seen := by
      rcases hnew with hnew | hnew
      · exact hnew
      · simp [shirudo] at hnew
    rcases hidle with hidle | hidle
    · obtain ⟨hg, hb, he⟩ := hi
      refine ⟨glob_newBoot _ s.w.mounted s.w.cfgPcr s.w.cfgImage hg hnew
          (Or.inr rfl), ?_, ?_⟩
      · simp only [hidle]
        trivial
      · simp only [hidle]
        trivial
    · simp [shirudo] at hidle
  | restart keep f hidle hkeep =>
    rcases hkeep with rfl | hkeep
    · exact hi
    · simp [shirudo] at hkeep

omit [DecidableEq R] in
theorem inv_fresh (b : B) (f : Nat → List D) (idx : Nat) (img : R) :
    Inv digest ⟨fresh b f idx img, .idle⟩ :=
  ⟨⟨⟨none, [], rfl, fun _ => ⟨rfl, rfl⟩, (fun r h => by cases h),
        (fun r h => by cases h)⟩,
      List.mem_cons_self, (fun r q h => by cases h), (fun e h => by cases h),
      (fun p h => by cases h), List.nodup_nil, (fun n h => by cases h),
      (fun r x h => by cases h), (fun m h => by cases h),
      (fun r h => by cases h)⟩,
    trivial, trivial⟩

theorem inv_star {s s' : Sys B R D} (hi : Inv digest s)
    (h : Star (Step digest shirudo) s s') :
    Inv digest s' := by
  induction h with
  | refl => exact hi
  | tail _ hstep ih => exact inv_step ih hstep

theorem inv_reachable {s : Sys B R D}
    (h : Reachable digest shirudo s) : Inv digest s := by
  obtain ⟨b, f, idx, img, h⟩ := h
  exact inv_star (inv_fresh b f idx img) h

end Inv

/-! ### Root's TPM

What holds when root suspends the target in the middle of a command or
brings a boot identity back with `TPM2_Clear`: the journal, the mount and
what the command in progress wrote, without the TPM boot and the PCR. -/

section RootDefs

variable {B R D : Type} [DecidableEq B] [DecidableEq R] [DecidableEq D]
variable (digest : Kind → R → D)

/-- The facts of `Glob` that no TPM boot change touches. -/
structure GlobW (w : World B R D) : Prop where
  journal : ∃ last x, scan digest w.events = some (last, x) ∧
    (w.state = none → w.events = [] ∧ w.torn = false) ∧
    (∀ r, w.state = some ⟨r, false⟩ → last = some r ∧ w.torn = false) ∧
    (∀ r, w.state = some ⟨r, true⟩ → last = some r ∨ Follows last r)
  mounted_state : ∀ m, w.mounted = some m →
    ∃ r q, w.state = some ⟨r, q⟩ ∧ (m = r.root ∨ q = true)

/-- `Base` without the TPM boot and the PCR. -/
def BaseW (w : World B R D) : Proc B R D → Prop
  | .idle => True
  | .starting .update _ prev =>
    ∃ r, prev = some r ∧ w.state = some ⟨r, false⟩
  | .starting .boot _ _ => True
  | .saving _ _ => True
  | .extending e _ => w.state = some ⟨e, true⟩
  | .readback e _ => w.state = some ⟨e, true⟩
  | .appending e => w.state = some ⟨e, true⟩
  | .activating e => w.state = some ⟨e, true⟩
  | .restOfInit true sel => ∃ e, w.state = some ⟨e, true⟩ ∧
      e.kind = .boot ∧ e.root = sel ∧ w.mounted = some sel
  | .restOfInit false _ => True
  | .checking sel => ∃ e, w.state = some ⟨e, true⟩ ∧
      w.mounted = some e.root ∧
      (∀ s, sel = some s → e.kind = .boot ∧ e.root = s) ∧
      (sel = none → e.kind = .update)
  | .marking r sel => w.state = some ⟨r, true⟩ ∧ w.mounted = some r.root ∧
      (∀ s, sel = some s → r.kind = .boot ∧ r.root = s) ∧
      (sel = none → r.kind = .update) ∧
      ∃ x, scan digest w.events = some (some r, x) ∧ w.torn = false
  | .marked r sel => w.state = some ⟨r, false⟩ ∧ w.mounted = some r.root ∧
      (∀ s, sel = some s → r.kind = .boot ∧ r.root = s) ∧
      (sel = none → r.kind = .update)

/-- `Ext` without the TPM boot and the extensions sent. -/
def ExtW (w : World B R D) : Proc B R D → Prop
  | .starting .boot _ prev => ∃ x, scan digest w.events = some (prev, x)
  | .saving e _ =>
      ∃ last x, scan digest w.events = some (last, x) ∧ Follows last e
  | _ => True

/-- The invariant on root's TPM. -/
def InvW (s : Sys B R D) : Prop :=
  GlobW digest s.w ∧ BaseW digest s.w s.proc ∧ ExtW digest s.w s.proc

end RootDefs

section Root

variable {B R D : Type} [DecidableEq B] [DecidableEq R] [DecidableEq D]
variable {digest : Kind → R → D}

theorem stepIn_root {s s' : Sys B R D} (h : StepIn digest shirudo s s') :
    StepIn digest rootTpm s s' := by
  cases h with
  | crash => exact .crash _ _
  | outsider w π i d => exact .outsider w π i d
  | startUpdate w t r h1 h2 h3 h4 h5 => exact .startUpdate w t r h1 h2 h3 h4 h5
  | initSame w r h1 h2 h3 h4 => exact .initSame w r h1 h2 h3 h4
  | initFirst w x h1 h2 h3 => exact .initFirst w x h1 h2 h3
  | initNew w r q last x h1 h2 h3 h4 h5 =>
    exact .initNew w r q last x h1 h2 h3 h4 h5
  | read w k t prev h1 => exact .read w k t prev h1
  | save w e b => exact .save w e b
  | extend w e b => exact .extend w e b
  | extendLost w e b => exact .extendLost w e b
  | readback w e b h1 h2 => exact .readback w e b h1 h2
  | append w e last x h1 h2 h3 => exact .append w e last x h1 h2 h3
  | appendTorn w e last x h1 h2 h3 => exact .appendTorn w e last x h1 h2 h3
  | appendTruncated w e last x h1 h2 h3 =>
    exact .appendTruncated w e last x h1 h2 h3
  | activateBoot w e h1 => exact .activateBoot w e h1
  | activateUpdate w e h1 => exact .activateUpdate w e h1
  | unmount w e => exact .unmount w e
  | initComplete w sel r q h1 h2 => exact .initComplete w sel r q h1 h2
  | initDone w sel r q h1 h2 h3 => exact .initDone w sel r q h1 h2 h3
  | check w sel r q h1 h2 => exact .check w sel r q h1 h2
  | mark w r sel => exact .mark w r sel
  | restore w r sel => exact .restore w r sel
  | stage w t r h1 h2 h3 => exact .stage w t r h1 h2 h3
  | unstage w r h1 h2 h3 => exact .unstage w r h1 h2 h3
  | clearStaged w r sel => exact .clearStaged w r sel
  | retry _ _ _ _ hv => simp [shirudo] at hv
  | recover _ _ hv => simp [shirudo] at hv

/-- Every run on a calm TPM is one on root's. -/
theorem step_root {s s' : Sys B R D} (h : Step digest shirudo s s') :
    Step digest rootTpm s s' := by
  cases h with
  | inBoot h => exact .inBoot (stepIn_root h)
  | reboot b f idx img hnew =>
    rcases hnew with hnew | hnew
    · exact .reboot _ b f idx img (Or.inl hnew)
    · simp [shirudo] at hnew
  | reset b keep f hidle hnew =>
    exact .reset _ b keep f (Or.inr rfl) (Or.inr rfl)
  | restart keep f hidle hkeep =>
    exact .restart _ keep f (Or.inr rfl) (Or.inr rfl)

theorem reachable_root {s : Sys B R D} (h : Reachable digest shirudo s) :
    Reachable digest rootTpm s := by
  obtain ⟨b, f, idx, img, h⟩ := h
  refine ⟨b, f, idx, img, ?_⟩
  induction h with
  | refl => exact Star.refl _
  | tail _ hstep ih => exact ih.tail (step_root hstep)

omit [DecidableEq R] in
theorem baseW_world {w w' : World B R D} {π : Proc B R D}
    (hb : BaseW digest w π) (hs : w'.state = w.state)
    (hm : w'.mounted = w.mounted) (he : w'.events = w.events)
    (ht : w'.torn = w.torn) : BaseW digest w' π := by
  cases π with
  | idle => trivial
  | starting k t prev => cases k <;> simp only [BaseW, hs] at hb ⊢ <;> exact hb
  | saving => trivial
  | extending => simp only [BaseW, hs] at hb ⊢; exact hb
  | readback => simp only [BaseW, hs] at hb ⊢; exact hb
  | appending => simp only [BaseW, hs] at hb ⊢; exact hb
  | activating => simp only [BaseW, hs] at hb ⊢; exact hb
  | restOfInit p sel =>
    cases p <;> simp only [BaseW, hs, hm] at hb ⊢ <;> exact hb
  | checking => simp only [BaseW, hs, hm] at hb ⊢; exact hb
  | marking => simp only [BaseW, hs, hm, he, ht] at hb ⊢; exact hb
  | marked => simp only [BaseW, hs, hm] at hb ⊢; exact hb

omit [DecidableEq R] in
theorem extW_world {w w' : World B R D} {π : Proc B R D}
    (hx : ExtW digest w π) (he : w'.events = w.events) :
    ExtW digest w' π := by
  cases π with
  | starting k t prev => cases k <;> simp only [ExtW, he] at hx ⊢ <;> exact hx
  | saving => simp only [ExtW, he] at hx ⊢; exact hx
  | idle => trivial
  | extending => trivial
  | readback => trivial
  | appending => trivial
  | activating => trivial
  | restOfInit => trivial
  | checking => trivial
  | marking => trivial
  | marked => trivial

/-- What the command in progress wrote holds from any journal, whatever
the TPM does. -/
theorem baseW_stepIn {s s' : Sys B R D} (hb : BaseW digest s.w s.proc)
    (h : StepIn digest rootTpm s s') : BaseW digest s'.w s'.proc := by
  cases h with
  | crash => trivial
  | outsider w π i d => exact baseW_world hb rfl rfl rfl rfl
  | startUpdate w t r hs => exact ⟨r, rfl, hs⟩
  | initSame => trivial
  | initFirst => trivial
  | initNew => trivial
  | read => trivial
  | save => rfl
  | extend => exact hb
  | extendLost => trivial
  | readback => exact hb
  | append => exact hb
  | appendTorn => trivial
  | appendTruncated => trivial
  | activateBoot w e hk => exact ⟨e, hb, hk, rfl, rfl⟩
  | activateUpdate w e hk =>
    exact ⟨e, hb, rfl, (fun _ h => by cases h), fun _ => hk⟩
  | unmount => trivial
  | initComplete w sel r q _ _ =>
    obtain ⟨e, h1, h3, h4, h5⟩ := hb
    refine ⟨e, h1, by rw [h5, h4], ?_, fun h => by cases h⟩
    intro s hs
    cases hs
    exact ⟨h3, h4⟩
  | initDone => trivial
  | check w sel r q hs hc =>
    obtain ⟨e, h1, h3, h4, h4'⟩ := hb
    rw [h1] at hs
    cases hs
    obtain ⟨x, hx, ht, -, -⟩ := checkRecord_ok.1 hc
    exact ⟨h1, h3, h4, h4', x, hx, ht⟩
  | mark w r sel =>
    obtain ⟨-, h3, h4, h4', -⟩ := hb
    exact ⟨rfl, h3, h4, h4'⟩
  | restore => trivial
  | stage => trivial
  | unstage => trivial
  | clearStaged => trivial
  | retry _ _ _ _ hv => simp [rootTpm] at hv
  | recover _ _ hv => simp [rootTpm] at hv

theorem baseW_step {s s' : Sys B R D} (hb : BaseW digest s.w s.proc)
    (h : Step digest rootTpm s s') : BaseW digest s'.w s'.proc := by
  cases h with
  | inBoot h => exact baseW_stepIn hb h
  | reboot => trivial
  | reset => exact baseW_world hb rfl rfl rfl rfl
  | restart => exact baseW_world hb rfl rfl rfl rfl

theorem baseW_star {s s' : Sys B R D} (hb : BaseW digest s.w s.proc)
    (h : Star (Step digest rootTpm) s s') : BaseW digest s'.w s'.proc := by
  induction h with
  | refl => exact hb
  | tail _ hstep ih => exact baseW_step ih hstep

omit [DecidableEq R] in
theorem globW_of {w w' : World B R D} (hg : GlobW digest w)
    (hs : w'.state = w.state) (hm : w'.mounted = w.mounted)
    (he : w'.events = w.events) (ht : w'.torn = w.torn) :
    GlobW digest w' := by
  obtain ⟨⟨last, x, hscan, h1, h2, h3⟩, hmo⟩ := hg
  refine ⟨⟨last, x, by rw [he]; exact hscan, ?_, ?_, ?_⟩, ?_⟩
  · intro h
    rw [hs] at h
    rw [he, ht]
    exact h1 h
  · intro r h
    rw [hs] at h
    rw [ht]
    exact h2 r h
  · intro r h
    rw [hs] at h
    exact h3 r h
  · intro m h
    rw [hm] at h
    rw [hs]
    exact hmo m h

theorem invW_stepIn {s s' : Sys B R D} (hi : InvW digest s)
    (h : StepIn digest rootTpm s s') : InvW digest s' := by
  obtain ⟨hg, hb, he⟩ := hi
  refine ⟨?_, baseW_stepIn hb h, ?_⟩
  · cases h with
    | crash => exact hg
    | outsider => exact globW_of hg rfl rfl rfl rfl
    | startUpdate => exact hg
    | initSame => exact hg
    | initFirst => exact hg
    | initNew => exact hg
    | read => exact hg
    | save w e b =>
      obtain ⟨last, x, hscan, hf⟩ := he
      exact ⟨⟨last, x, hscan, (fun h => by cases h), (fun r h => by cases h),
          fun r h => by cases h; exact Or.inr hf⟩,
        fun _ _ => ⟨e, true, rfl, Or.inr rfl⟩⟩
    | extend => exact globW_of hg rfl rfl rfl rfl
    | extendLost => exact globW_of hg rfl rfl rfl rfl
    | readback => exact hg
    | append w e last x _ hscan hf =>
      have hs : w.state = some ⟨e, true⟩ := hb
      exact ⟨⟨some e, fold digest e x, scan_cons.2 ⟨last, x, hscan, hf, rfl⟩,
          (fun h => by rw [hs] at h; cases h),
          (fun r h => by rw [hs] at h; cases h),
          (fun r h => by rw [hs] at h; cases h; exact Or.inl rfl)⟩,
        hg.mounted_state⟩
    | appendTorn w e =>
      have hs : w.state = some ⟨e, true⟩ := hb
      obtain ⟨last, x, hscan, -, -, hp⟩ := hg.journal
      exact ⟨⟨last, x, hscan, (fun h => by rw [hs] at h; cases h),
          (fun r h => by rw [hs] at h; cases h), hp⟩, hg.mounted_state⟩
    | appendTruncated w e =>
      have hs : w.state = some ⟨e, true⟩ := hb
      obtain ⟨last, x, hscan, -, -, hp⟩ := hg.journal
      exact ⟨⟨last, x, hscan, (fun h => by rw [hs] at h; cases h),
          (fun r h => by rw [hs] at h; cases h), hp⟩, hg.mounted_state⟩
    | activateBoot w e =>
      have hs : w.state = some ⟨e, true⟩ := hb
      exact ⟨hg.journal, fun _ _ => ⟨e, true, hs, Or.inr rfl⟩⟩
    | activateUpdate w e =>
      have hs : w.state = some ⟨e, true⟩ := hb
      exact ⟨hg.journal, fun _ _ => ⟨e, true, hs, Or.inr rfl⟩⟩
    | unmount => exact ⟨hg.journal, fun _ h => by cases h⟩
    | initComplete => exact hg
    | initDone => exact globW_of hg rfl rfl rfl rfl
    | check => exact hg
    | mark w r sel =>
      obtain ⟨-, hm, -, -, x, hx, ht⟩ := hb
      refine ⟨⟨some r, x, hx, (fun h => by cases h),
          (fun r' h => by cases h; exact ⟨rfl, ht⟩), (fun r' h => by cases h)⟩,
        fun m h => ?_⟩
      rw [hm] at h
      cases h
      exact ⟨r, false, rfl, Or.inl rfl⟩
    | restore w r sel =>
      obtain ⟨hs, -⟩ := hb
      obtain ⟨last, x, hscan, -, hnp, -⟩ := hg.journal
      exact ⟨⟨last, x, hscan, (fun h => by cases h), (fun r' h => by cases h),
          fun r' h => by cases h; exact Or.inl (hnp r hs).1⟩,
        fun _ _ => ⟨r, true, rfl, Or.inr rfl⟩⟩
    | stage => exact globW_of hg rfl rfl rfl rfl
    | unstage => exact globW_of hg rfl rfl rfl rfl
    | clearStaged => exact globW_of hg rfl rfl rfl rfl
    | retry _ _ _ _ hv => simp [rootTpm] at hv
    | recover _ _ hv => simp [rootTpm] at hv
  · cases h with
    | outsider w π i d => exact extW_world he rfl
    | initFirst w x _ hscan _ => exact ⟨x, hscan⟩
    | initNew w r q last x _ _ hscan _ _ => exact ⟨x, hscan⟩
    | read w k t prev hf =>
      cases k with
      | boot =>
        obtain ⟨x, hx⟩ := he
        exact ⟨prev, x, hx, hf⟩
      | update =>
        obtain ⟨r, hprev, hs⟩ := hb
        subst hprev
        obtain ⟨last, x, hscan, -, hnp, -⟩ := hg.journal
        obtain ⟨hlast, -⟩ := hnp r hs
        subst hlast
        exact ⟨some r, x, hscan, hf⟩
    | retry _ _ _ _ hv => simp [rootTpm] at hv
    | recover _ _ hv => simp [rootTpm] at hv
    | _ => trivial

theorem invW_step {s s' : Sys B R D} (hi : InvW digest s)
    (h : Step digest rootTpm s s') : InvW digest s' := by
  cases h with
  | inBoot h => exact invW_stepIn hi h
  | reboot => exact ⟨⟨hi.1.journal, fun _ h => by cases h⟩, trivial, trivial⟩
  | reset =>
    exact ⟨globW_of hi.1 rfl rfl rfl rfl, baseW_world hi.2.1 rfl rfl rfl rfl,
      extW_world hi.2.2 rfl⟩
  | restart =>
    exact ⟨globW_of hi.1 rfl rfl rfl rfl, baseW_world hi.2.1 rfl rfl rfl rfl,
      extW_world hi.2.2 rfl⟩

theorem invW_reachable {s : Sys B R D}
    (h : Reachable digest rootTpm s) : InvW digest s := by
  obtain ⟨b, f, idx, img, h⟩ := h
  have h0 : InvW digest ⟨fresh b f idx img, .idle⟩ :=
    ⟨⟨⟨none, [], rfl, fun _ => ⟨rfl, rfl⟩, (fun r h => by cases h),
        (fun r h => by cases h)⟩, fun m h => by cases h⟩, trivial, trivial⟩
  induction h with
  | refl => exact h0
  | tail _ hstep ih => exact invW_step ih hstep

end Root

/-! ### (a) Consistent, or refusing until the TPM boot changes -/

section Refusal

variable {B R D : Type} [DecidableEq B] [DecidableEq R] [DecidableEq D]
variable {digest : Kind → R → D}

theorem pendingHere_refuses {w : World B R D}
    (h : PendingHere w) : check digest w = .einprogress := by
  obtain ⟨r, hs, -⟩ := h
  simp [check, hs]

theorem drift_refuses {w : World B R D}
    (h : Drift digest w) : check digest w = .euclean := by
  obtain ⟨r, x, xs, hs, hb, hx, ht, hne, hp⟩ := h
  have hlen : (xs ++ x) ≠ x := by
    intro he
    have := congrArg List.length he
    simp only [List.length_append] at this
    exact hne (List.eq_nil_of_length_eq_zero (by omega))
  simp [check, hs, checkRecord, hx, ht, hb, hp, hlen]

theorem stale_refuses {w : World B R D} (h : Stale w) :
    check digest w ≠ .ok := by
  intro hc
  obtain ⟨r, hs, hr⟩ := check_ok.1 hc
  obtain ⟨x, -, -, hb, -⟩ := checkRecord_ok.1 hr
  exact h r false hs hb.symm

/-- (a) At every point of every sequence of commands, interruptions and
boots, the config PCR replays from the record and the selected config is
mounted, so commands run; or `config_update_check()` refuses, because a
selection of this TPM boot is pending, because something else extended
the PCR, or because `init` has not recorded this TPM boot. A journal that
cannot be read is never among them. -/
theorem consistent_or_refusing {s : Sys B R D}
    (h : Reachable digest shirudo s) :
    Admits digest s.w ∨
      (PendingHere s.w ∧ check digest s.w = .einprogress) ∨
      (Drift digest s.w ∧ check digest s.w = .euclean) ∨
      (Stale s.w ∧ check digest s.w ≠ .ok) := by
  obtain ⟨hg, -, -⟩ := inv_reachable h
  cases hs : s.w.state with
  | none =>
    have hst : Stale s.w := fun r q h => by rw [hs] at h; cases h
    exact Or.inr (Or.inr (Or.inr ⟨hst, stale_refuses hst⟩))
  | some rec =>
    obtain ⟨r, q⟩ := rec
    by_cases hb : r.boot = s.w.boot
    · cases q with
      | true =>
        have hp : PendingHere s.w := ⟨r, hs, hb⟩
        exact Or.inr (Or.inl ⟨hp, pendingHere_refuses hp⟩)
      | false =>
        obtain ⟨last, x, hscan, -, hnp, -⟩ := hg.journal
        obtain ⟨hlast, ht⟩ := hnp r hs
        subst hlast
        obtain ⟨xs, hxs⟩ := hg.suffix r x hs hb hscan
        cases xs with
        | nil =>
          left
          refine ⟨check_ok.2
              ⟨r, hs, checkRecord_ok.2 ⟨x, hscan, ht, hb.symm, hxs⟩⟩, r, hs,
            hg.state_mounted r hs hb⟩
        | cons d ds =>
          have hd : Drift digest s.w :=
            ⟨r, x, d :: ds, hs, hb, hscan, ht, by simp, hxs⟩
          exact Or.inr (Or.inr (Or.inl ⟨hd, drift_refuses hd⟩))
    · have hst : Stale s.w := by
        intro r' q' h
        rw [hs] at h
        cases h
        exact hb
      exact Or.inr (Or.inr (Or.inr ⟨hst, stale_refuses hst⟩))

/-- A pending selection or a drift of this TPM boot, with only other
processes' extensions since. -/
def Blocked (dg : Kind → R → D) (s0 s : Sys B R D) : Prop :=
  s.proc = .idle ∧ s.w.state = s0.w.state ∧ s.w.events = s0.w.events ∧
    s.w.torn = s0.w.torn ∧ s.w.mounted = s0.w.mounted ∧ s.w.sent = s0.w.sent ∧
    s.w.boot = s0.w.boot ∧ (PendingHere s.w ∨ Drift dg s.w)

omit [DecidableEq R] in
theorem drift_outsider {w : World B R D} (i : Nat) (d : D)
    (h : Drift digest w) :
    Drift digest { w with pcr := extendAt w.pcr i d } := by
  obtain ⟨r, x, xs, hs, hb, hx, ht, hne, hp⟩ := h
  by_cases hi : r.pcr = i
  · refine ⟨r, x, d :: xs, hs, hb, hx, ht, by simp, ?_⟩
    show extendAt w.pcr i d r.pcr = _
    simp [extendAt, hi] at hp ⊢
    simp [hp]
  · exact ⟨r, x, xs, hs, hb, hx, ht, hne, by simp [extendAt, hi, hp]⟩

theorem blocked_step {s0 s s' : Sys B R D} (hbl : Blocked digest s0 s)
    (h : StepIn digest shirudo s s') : Blocked digest s0 s' := by
  obtain ⟨hidle, hst, hev, hto, hmo, hse, hbo, hcase⟩ := hbl
  have hrefuse : check digest s.w ≠ .ok := by
    rcases hcase with hc | hc
    · rw [pendingHere_refuses hc]
      simp
    · rw [drift_refuses hc]
      simp
  have hnotstale : ∀ r q, s.w.state = some ⟨r, q⟩ → r.boot = s.w.boot := by
    intro r q hs
    rcases hcase with ⟨r', hs', hb'⟩ | ⟨r', _, _, hs', hb', _⟩ <;>
      (rw [hs] at hs'; cases hs'; exact hb')
  cases h with
  | crash w π => exact ⟨rfl, hst, hev, hto, hmo, hse, hbo, hcase⟩
  | outsider w π i d =>
    refine ⟨hidle, hst, hev, hto, hmo, hse, hbo, ?_⟩
    rcases hcase with ⟨r, hs, hb⟩ | hc
    · exact Or.inl ⟨r, hs, hb⟩
    · exact Or.inr (drift_outsider i d hc)
  | startUpdate _ _ _ _ hc => exact absurd hc hrefuse
  | initSame _ _ _ _ _ hc => exact absurd hc hrefuse
  | initFirst w x hs =>
    rcases hcase with ⟨r, hs', -⟩ | ⟨r, _, _, hs', -⟩ <;>
      (rw [hs] at hs'; cases hs')
  | initNew w r q last x hs hb => exact absurd (hnotstale r q hs) hb
  | read => cases hidle
  | save => cases hidle
  | extend => cases hidle
  | extendLost => cases hidle
  | readback => cases hidle
  | append => cases hidle
  | appendTorn => cases hidle
  | appendTruncated => cases hidle
  | activateBoot => cases hidle
  | activateUpdate => cases hidle
  | unmount => cases hidle
  | initComplete => cases hidle
  | initDone => cases hidle
  | check => cases hidle
  | mark => cases hidle
  | restore => cases hidle
  | stage _ _ _ _ hc => exact absurd hc hrefuse
  | unstage _ _ _ hc => exact absurd hc hrefuse
  | clearStaged => cases hidle
  | retry _ _ _ _ hv => simp [shirudo] at hv
  | recover _ _ hv => simp [shirudo] at hv

/-- (a) A pending selection or a drift of this TPM boot lasts until the
TPM boot changes: whatever runs, retries, crashes or extends the PCR,
the journal, the mount and shirudo's extensions stay as they are, no
command starts, and every target command but `status` and `image
status` refuses. -/
theorem refusal_persists {s s' : Sys B R D} (h : Reachable digest shirudo s)
    (hidle : s.proc = .idle) (hnot : ¬ Admits digest s.w) (hboot : ¬ Stale s.w)
    (hrun : Star (StepIn digest shirudo) s s') :
    s'.proc = .idle ∧ s'.w.state = s.w.state ∧ s'.w.events = s.w.events ∧
      s'.w.torn = s.w.torn ∧ s'.w.mounted = s.w.mounted ∧
      s'.w.sent = s.w.sent ∧ s'.w.boot = s.w.boot ∧
      check digest s'.w ≠ .ok ∧ ¬ Admits digest s'.w := by
  have h0 : Blocked digest s s := by
    refine ⟨hidle, rfl, rfl, rfl, rfl, rfl, rfl, ?_⟩
    rcases consistent_or_refusing h with ha | ⟨hp, -⟩ | ⟨hd, -⟩ | ⟨hst, -⟩
    · exact absurd ha hnot
    · exact Or.inl hp
    · exact Or.inr hd
    · exact absurd hst hboot
  have hb : Blocked digest s s' := by
    induction hrun with
    | refl => exact h0
    | tail _ hstep ih => exact blocked_step ih hstep
  obtain ⟨h1, h2, h3, h4, h5, h6, h7, hcase⟩ := hb
  have hrefuse : check digest s'.w ≠ .ok := by
    rcases hcase with hc | hc
    · rw [pendingHere_refuses hc]
      simp
    · rw [drift_refuses hc]
      simp
  exact ⟨h1, h2, h3, h4, h5, h6, h7, hrefuse, fun ha => hrefuse ha.1⟩

end Refusal

/-! ### (b) One extension per activation and TPM boot -/

section Once

variable {B R D : Type} [DecidableEq B] [DecidableEq R] [DecidableEq D]
variable {digest : Kind → R → D}

/-- (b) shirudo sends the config PCR at most one extension for each
activation, numbered by its sequence, within a TPM boot: an ambiguous
extension is never sent again. -/
theorem extends_once {s : Sys B R D}
    (h : Reachable digest shirudo s) : s.w.sent.Nodup :=
  (inv_reachable h).1.sent_nodup

/-- (b) On root's TPM too, shirudo extends the config PCR only right
after the command's `state_save()`, for the record it saved, with that
record durable as pending. -/
theorem extension_follows_save {s s' : Sys B R D}
    (h : Reachable digest rootTpm s)
    (hstep : StepIn digest rootTpm s s') (hsent : s'.w.sent ≠ s.w.sent) :
    ∃ e b, s.proc = .extending e b ∧ s.w.state = some ⟨e, true⟩ ∧
      s'.w.sent = (s.w.boot, e.seq) :: s.w.sent := by
  obtain ⟨-, hb, -⟩ := invW_reachable h
  cases hstep with
  | extend w e b => exact ⟨e, b, rfl, hb, rfl⟩
  | extendLost w e b => exact ⟨e, b, rfl, hb, rfl⟩
  | retry _ _ _ _ hv => simp [rootTpm] at hv
  | _ => exact absurd rfl hsent

/-- (b) shirudo extends the config PCR only with the pending record of
this TPM boot durable, for that record's activation; the extensions of
the TPM boot so far are of that activation or earlier ones. -/
theorem extension_follows_pending {s s' : Sys B R D}
    (h : Reachable digest shirudo s)
    (hstep : StepIn digest shirudo s s') (hsent : s'.w.sent ≠ s.w.sent) :
    ∃ e b, s.proc = .extending e b ∧ s.w.state = some ⟨e, true⟩ ∧
      e.boot = s.w.boot ∧ s'.w.sent = (s.w.boot, e.seq) :: s.w.sent ∧
      ∀ n, (s.w.boot, n) ∈ s.w.sent → n < e.seq := by
  obtain ⟨-, hb, he⟩ := inv_reachable h
  cases hstep with
  | extend w e b => exact ⟨e, b, rfl, hb.1, hb.2, rfl, he⟩
  | extendLost w e b => exact ⟨e, b, rfl, hb.1, hb.2, rfl, he⟩
  | retry _ _ _ _ hv => simp [shirudo] at hv
  | crash => exact absurd rfl hsent
  | outsider => exact absurd rfl hsent
  | startUpdate => exact absurd rfl hsent
  | initSame => exact absurd rfl hsent
  | initFirst => exact absurd rfl hsent
  | initNew => exact absurd rfl hsent
  | read => exact absurd rfl hsent
  | save => exact absurd rfl hsent
  | readback => exact absurd rfl hsent
  | append => exact absurd rfl hsent
  | appendTorn => exact absurd rfl hsent
  | appendTruncated => exact absurd rfl hsent
  | activateBoot => exact absurd rfl hsent
  | activateUpdate => exact absurd rfl hsent
  | unmount => exact absurd rfl hsent
  | initComplete => exact absurd rfl hsent
  | initDone => exact absurd rfl hsent
  | check => exact absurd rfl hsent
  | mark => exact absurd rfl hsent
  | restore => exact absurd rfl hsent
  | stage => exact absurd rfl hsent
  | unstage => exact absurd rfl hsent
  | clearStaged => exact absurd rfl hsent
  | recover => exact absurd rfl hsent

/-- (b) After an interruption that leaves the selection pending, shirudo
never extends the config PCR again in that TPM boot. -/
theorem interrupted_never_extends {s s' : Sys B R D}
    (h : Reachable digest shirudo s)
    (hidle : s.proc = .idle) (hp : PendingHere s.w)
    (hrun : Star (StepIn digest shirudo) s s') : s'.w.sent = s.w.sent := by
  have hnot : ¬ Admits digest s.w := fun ha =>
    absurd ha.1 (by rw [pendingHere_refuses hp]; simp)
  have hboot : ¬ Stale s.w := by
    obtain ⟨r, hs, hb⟩ := hp
    exact fun hst => hst r true hs hb
  exact (refusal_persists h hidle hnot hboot hrun).2.2.2.2.2.1

end Once

/-! ### (d) The config in use -/

section InUse

variable {B R D : Type} [DecidableEq B] [DecidableEq R] [DecidableEq D]
variable {digest : Kind → R → D}

/-- (d) A config a command runs with is the one the record selects:
consistent, or for `status` pending and mounted. This holds of every
world, as it restates `configInUse`; that `configInUse` is what
`current_config()` and `status_config()` give is by review. -/
theorem configInUse_vouched {w : World B R D} {st : Bool} {m : R}
    (h : configInUse digest w st = some m) :
    ∃ r q, w.state = some ⟨r, q⟩ ∧ m = r.root ∧ w.mounted = some m ∧
      ((q = false ∧ check digest w = .ok) ∨ (q = true ∧ st = true)) := by
  unfold configInUse at h
  cases hs : w.state with
  | none => simp [hs] at h
  | some rec =>
    obtain ⟨r, q⟩ := rec
    cases q with
    | false =>
      simp only [hs] at h
      by_cases hc : check digest w = .ok ∧ w.mounted = some r.root
      · simp only [hc, and_self, ite_true, Option.some.injEq] at h
        subst h
        exact ⟨r, false, rfl, rfl, hc.2, Or.inl ⟨rfl, hc.1⟩⟩
      · simp [hc] at h
    | true =>
      simp only [hs] at h
      by_cases hc : st = true ∧ w.mounted = some r.root
      · simp only [hc, and_self, ite_true, Option.some.injEq] at h
        subst h
        exact ⟨r, true, rfl, rfl, hc.2, Or.inr ⟨rfl, hc.1⟩⟩
      · simp [hc] at h

/-- (d) Whatever config is mounted is the one the record selects, except
while that selection is pending, on root's TPM too. -/
theorem mounted_selected {s : Sys B R D} {m : R}
    (h : Reachable digest rootTpm s)
    (hm : s.w.mounted = some m) :
    ∃ r q, s.w.state = some ⟨r, q⟩ ∧ (m = r.root ∨ q = true) :=
  (invW_reachable h).1.mounted_state m hm

/-- (d) A consistent record always has its config mounted, so commands
never run with another, and never fail for want of it. -/
theorem consistent_mounted {s : Sys B R D} (h : Reachable digest shirudo s)
    (hc : check digest s.w = .ok) : Admits digest s.w ∧
      ∃ r, s.w.state = some ⟨r, false⟩ ∧
        configInUse digest s.w false = some r.root ∧
        configInUse digest s.w true = some r.root := by
  obtain ⟨r, hs, hr⟩ := check_ok.1 hc
  obtain ⟨x, -, -, hb, -⟩ := checkRecord_ok.1 hr
  have hm := (inv_reachable h).1.state_mounted r hs hb.symm
  refine ⟨⟨hc, r, hs, hm⟩, r, hs, ?_, ?_⟩ <;> simp [configInUse, hs, hc, hm]

end InUse

/-! ### (e) The journal and the PCR -/

section Journal

variable {B R D : Type} [DecidableEq B] [DecidableEq R] [DecidableEq D]
variable {digest : Kind → R → D}

/-- (e) No interruption leaves a journal a later boot cannot read: every
line follows the one before, a partial last line and a record ahead of
the journal occur only while the selection is pending, and a completed
record is the last line, on root's TPM too. -/
theorem journal_wellformed {s : Sys B R D} (h : Reachable digest rootTpm s) :
    ∃ last x, scan digest s.w.events = some (last, x) ∧
      (s.w.state = none → s.w.events = [] ∧ s.w.torn = false) ∧
      (∀ r, s.w.state = some ⟨r, false⟩ → last = some r ∧ s.w.torn = false) ∧
      (∀ r, s.w.state = some ⟨r, true⟩ → last = some r ∨ Follows last r) :=
  (invW_reachable h).1.journal

/-- (e) For a completed record of this TPM boot the PCR is the journal's
replay with nothing under it, and only other processes' extensions on
top: shirudo's own extensions are all in the journal. -/
theorem pcr_replay {s : Sys B R D} {r : Event B R D}
    (h : Reachable digest shirudo s)
    (hs : s.w.state = some ⟨r, false⟩) (hb : r.boot = s.w.boot) :
    ∃ x xs, scan digest s.w.events = some (some r, x) ∧
      s.w.pcr r.pcr = xs ++ x := by
  obtain ⟨hg, -, -⟩ := inv_reachable h
  obtain ⟨last, x, hscan, -, hnp, -⟩ := hg.journal
  obtain ⟨hlast, -⟩ := hnp r hs
  subst hlast
  obtain ⟨xs, hxs⟩ := hg.suffix r x hs hb hscan
  exact ⟨x, xs, hscan, hxs⟩

end Journal

/-! ### (c) The staged config -/

section Staged

variable {B R D : Type} [DecidableEq B] [DecidableEq R] [DecidableEq D]
variable {digest : Kind → R → D}

/-- What `next-boot` keeps true: a stage is of the record or of an
earlier one, and one with the record's sequence number is that record,
completed, with the root it stages. -/
def StagedOk (w : World B R D) : Prop :=
  ∀ st, w.staged = some st → ∃ r q, w.state = some ⟨r, q⟩ ∧ st.seq ≤ r.seq ∧
    (st.seq = r.seq → q = false ∧ st = { r with root := st.root })

/-- What the command in progress keeps of the stage: the record it saves
or completes is later than the stage. -/
def StagedProc (w : World B R D) : Proc B R D → Prop
  | .saving e _ => ∀ st, w.staged = some st → st.seq < e.seq
  | .marked r _ => ∀ st, w.staged = some st → st.seq < r.seq
  | _ => True

omit [DecidableEq B] [DecidableEq R] [DecidableEq D] in
theorem stagedOk_keep {w : World B R D} {st : Option (Event B R D)}
    (hk : StagedOk w) (hsub : ∀ x, st = some x → w.staged = some x) :
    StagedOk { w with staged := st } :=
  fun x hx => hk x (hsub x hx)

omit [DecidableEq R] [DecidableEq D] in
theorem keepStaged_sub {st : Option (Event B R D)} {r : Event B R D} :
    ∀ x, keepStaged st r = some x → st = some x := by
  intro x hx
  cases st with
  | none => cases hx
  | some y =>
    simp only [keepStaged] at hx
    split at hx
    · exact hx
    · cases hx

omit [DecidableEq R] in
/-- A record `read` builds is later than the stage. -/
theorem staged_read {w : World B R D} {k : Kind} {t : R}
    {prev : Option (Event B R D)} (hi : Inv digest ⟨w, .starting k t prev⟩)
    (hk : StagedOk w) :
    ∀ st, w.staged = some st → st.seq < (newEvent w k t prev).seq := by
  intro st hst
  obtain ⟨r, q, hs, hle, heq⟩ := hk st hst
  obtain ⟨hg, hb, he⟩ := hi
  have hprev : ∀ p, prev = some p → st.seq ≤ p.seq →
      st.seq < (newEvent w k t prev).seq := by
    intro p hp hlep
    subst hp
    show st.seq < p.seq + 1
    omega
  cases k with
  | update =>
    obtain ⟨r', hpr, hs', -⟩ := hb
    rw [hs] at hs'
    cases hs'
    exact hprev r hpr hle
  | boot =>
    obtain ⟨⟨x, hx⟩, -⟩ := he
    obtain ⟨last, x', hscan, -, hnp, hpend⟩ := hg.journal
    rw [hx] at hscan
    cases hscan
    cases q with
    | false =>
      exact hprev r (hnp r hs).1 hle
    | true =>
      have hlt : st.seq < r.seq := by
        rcases Nat.lt_or_ge st.seq r.seq with h | h
        · exact h
        · have := (heq (Nat.le_antisymm hle h)).1
          cases this
      rcases hpend r hs with hl | hl
      · exact hprev r hl hle
      · cases prev with
        | none =>
          simp only [Follows] at hl
          show st.seq < 0 + 1
          omega
        | some p =>
          obtain ⟨hseq, -, -⟩ := hl
          exact hprev p rfl (by omega)

theorem staged_stepIn {s s' : Sys B R D} (hi : Inv digest s)
    (hk : StagedOk s.w) (hp : StagedProc s.w s.proc)
    (h : StepIn digest shirudo s s') :
    StagedOk s'.w ∧ StagedProc s'.w s'.proc := by
  cases h with
  | crash => exact ⟨hk, trivial⟩
  | outsider w π i d =>
    refine ⟨hk, ?_⟩
    cases π <;> first | exact hp | trivial
  | startUpdate => exact ⟨hk, trivial⟩
  | initSame => exact ⟨hk, trivial⟩
  | initFirst => exact ⟨hk, trivial⟩
  | initNew => exact ⟨hk, trivial⟩
  | read w k t prev _ => exact ⟨hk, staged_read hi hk⟩
  | save w e b =>
    refine ⟨fun st hst => ⟨e, true, rfl, Nat.le_of_lt (hp st hst), ?_⟩, trivial⟩
    intro heq
    exact absurd heq (Nat.ne_of_lt (hp st hst))
  | extend => exact ⟨hk, trivial⟩
  | extendLost => exact ⟨hk, trivial⟩
  | readback => exact ⟨hk, trivial⟩
  | append => exact ⟨hk, trivial⟩
  | appendTorn => exact ⟨hk, trivial⟩
  | appendTruncated => exact ⟨hk, trivial⟩
  | activateBoot => exact ⟨hk, trivial⟩
  | activateUpdate => exact ⟨hk, trivial⟩
  | unmount => exact ⟨hk, trivial⟩
  | initComplete => exact ⟨hk, trivial⟩
  | initDone => exact ⟨stagedOk_keep hk keepStaged_sub, trivial⟩
  | check => exact ⟨hk, trivial⟩
  | mark w r sel =>
    obtain ⟨-, hb, -⟩ := hi
    have hs : w.state = some ⟨r, true⟩ := hb.1
    have hlt : ∀ st, w.staged = some st → st.seq < r.seq := by
      intro st hst
      obtain ⟨r', q', hs', hle, heq⟩ := hk st hst
      rw [hs] at hs'
      cases hs'
      rcases Nat.lt_or_ge st.seq r.seq with h | h
      · exact h
      · cases (heq (Nat.le_antisymm hle h)).1
    refine ⟨fun st hst => ⟨r, false, rfl, Nat.le_of_lt (hlt st hst),
      fun heq => absurd heq (Nat.ne_of_lt (hlt st hst))⟩, hlt⟩
  | restore w r sel =>
    exact ⟨fun st hst => ⟨r, true, rfl, Nat.le_of_lt (hp st hst),
      fun heq => absurd heq (Nat.ne_of_lt (hp st hst))⟩, trivial⟩
  | stage w t r hs _ _ =>
    refine ⟨fun st hst => ⟨r, false, hs, ?_, fun _ => ⟨rfl, ?_⟩⟩, trivial⟩
    · cases hst
      exact Nat.le_refl _
    · cases hst
      rfl
  | unstage => exact ⟨fun st hst => (by cases hst), trivial⟩
  | clearStaged w r sel =>
    refine ⟨stagedOk_keep hk ?_, trivial⟩
    intro x hx
    cases sel with
    | none => cases hx
    | some _ => exact keepStaged_sub x hx
  | retry _ _ _ _ hv => simp [shirudo] at hv
  | recover _ _ hv => simp [shirudo] at hv

theorem staged_step {s s' : Sys B R D} (hi : Inv digest s)
    (hk : StagedOk s.w) (hp : StagedProc s.w s.proc)
    (h : Step digest shirudo s s') :
    StagedOk s'.w ∧ StagedProc s'.w s'.proc := by
  cases h with
  | inBoot h => exact staged_stepIn hi hk hp h
  | reboot => exact ⟨hk, trivial⟩
  | reset b keep f hidle _ =>
    rcases hidle with hidle | hidle
    · refine ⟨hk, ?_⟩
      simp only [hidle]
      trivial
    · simp [shirudo] at hidle
  | restart keep f hidle _ =>
    rcases hidle with hidle | hidle
    · refine ⟨hk, ?_⟩
      simp only [hidle]
      trivial
    · simp [shirudo] at hidle

theorem staged_reachable {s : Sys B R D} (h : Reachable digest shirudo s) :
    StagedOk s.w ∧ StagedProc s.w s.proc := by
  obtain ⟨b, f, idx, img, h⟩ := h
  have : Inv digest s ∧ StagedOk s.w ∧ StagedProc s.w s.proc := by
    induction h with
    | refl =>
      exact ⟨inv_fresh b f idx img, fun st hst => (by cases hst), trivial⟩
    | tail _ hstep ih =>
      obtain ⟨hi, hk, hp⟩ := ih
      exact ⟨inv_step hi hstep, staged_step hi hk hp hstep⟩
  exact this.2

/-- (c) `init` takes a staged root, rather than the record's, only when
the stage copies the record it starts from, completed, with another
root, and is of an earlier TPM boot: a stage that an activation
followed, or made in this TPM boot, is never taken. -/
theorem staged_taken {s : Sys B R D} (h : Reachable digest shirudo s)
    {r : Event B R D} {q : Bool} (hs : s.w.state = some ⟨r, q⟩)
    (ht : bootTarget s.w r ≠ r.root) :
    q = false ∧ ∃ st, s.w.staged = some st ∧
      st = { r with root := bootTarget s.w r } ∧ st.boot ≠ s.w.boot := by
  have hk := (staged_reachable h).1
  cases hst : s.w.staged with
  | none => simp [bootTarget, hst] at ht
  | some st =>
    by_cases hc : st.boot ≠ s.w.boot ∧ st.root ≠ r.root ∧ st.seq = r.seq ∧
        st.boot = r.boot
    · have hbt : bootTarget s.w r = st.root := by
        simp only [bootTarget, hst]
        split
        · rfl
        · next hn => exact absurd hc hn
      rw [hbt]
      obtain ⟨r', q', hs', -, heq⟩ := hk st hst
      rw [hs] at hs'
      cases hs'
      obtain ⟨hq, hst'⟩ := heq hc.2.2.1
      exact ⟨hq, st, rfl, hst', hc.1⟩
    · have hbt : bootTarget s.w r = r.root := by
        simp only [bootTarget, hst]
        split
        · next hy => exact absurd hy hc
        · rfl
      exact absurd hbt ht

end Staged

/-! ### (c) Startup after a reboot -/

section Boot

variable {B R D : Type} [DecidableEq B] [DecidableEq R] [DecidableEq D]
variable {digest : Kind → R → D}

theorem Star.mono {α : Type} {r r' : α → α → Prop} (hr : ∀ a b, r a b → r' a b)
    {a b : α} (h : Star r a b) : Star r' a b := by
  induction h with
  | refl => exact Star.refl _
  | tail _ hab ih => exact ih.tail (hr _ _ hab)

theorem Star.trans {α : Type} {r : α → α → Prop} {a b c : α} (h1 : Star r a b)
    (h2 : Star r b c) : Star r a c := by
  induction h2 with
  | refl => exact h1
  | tail _ hbc ih => exact ih.tail hbc

omit [DecidableEq R] in
theorem scan_last {es : List (Event B R D)} {e : Event B R D} {x : List D}
    (h : scan digest es = some (some e, x)) :
    e ∈ es ∧ ∃ run, x = fold digest e run := by
  cases es with
  | nil => simp [scan] at h
  | cons e' es =>
    obtain ⟨last, run, -, -, hp⟩ := scan_cons.1 h
    cases hp
    exact ⟨List.mem_cons_self, run, rfl⟩

/-- A boot event for root `t` over `last`, and `init` to its end. -/
def booted (dg : Kind → R → D) (w : World B R D) (t : R)
    (last : Option (Event B R D)) : World B R D :=
  { w with
    state := some ⟨newEvent w .boot t last, false⟩
    events := newEvent w .boot t last :: w.events
    torn := false
    pcr := extendAt w.pcr w.cfgPcr (dg .boot t)
    sent := (w.boot, (newEvent w .boot t last).seq) :: w.sent
    mounted := some t }

/-- `begin_event()` of a boot event and the rest of `init`, nothing
failing. -/
theorem boot_run {v : Variant} (w : World B R D) (t : R)
    (last : Option (Event B R D)) (x : List D)
    (hscan : scan digest w.events = some (last, x))
    (hf : Follows last (newEvent w .boot t last)) :
    Star (StepIn digest v) ⟨w, .starting .boot t last⟩
      ⟨booted digest w t last, .idle⟩ := by
  have hp : extendAt w.pcr w.cfgPcr (digest .boot t) w.cfgPcr =
      digest .boot t :: w.pcr w.cfgPcr := extendAt_self _ _ _
  exact ((((((((((Star.refl _).tail (StepIn.read w .boot t last hf)).tail
    (StepIn.save _ _ _)).tail (StepIn.extend _ _ _)).tail
    (StepIn.readback _ _ _ rfl hp)).tail
    (StepIn.append _ _ last x (fun _ => rfl) hscan hf)).tail
    (StepIn.activateBoot _ _ rfl)).tail
    (StepIn.initComplete _ _ _ true rfl rfl)).tail
    (StepIn.check _ _ _ true rfl
      (checkRecord_ok.2
          ⟨_, scan_cons.2 ⟨last, x, hscan, hf, rfl⟩, rfl, rfl, hp⟩))).tail
    (StepIn.mark _ _ _)).tail (StepIn.crash _ _)

theorem booted_admits (w : World B R D) (t : R)
    (last : Option (Event B R D)) (x : List D)
    (hscan : scan digest w.events = some (last, x))
    (hf : Follows last (newEvent w .boot t last)) :
    Admits digest (booted digest w t last) :=
  ⟨check_ok.2 ⟨_, rfl, checkRecord_ok.2
    ⟨_, scan_cons.2 ⟨last, x, hscan, hf, rfl⟩, rfl, rfl, extendAt_self _ _ _⟩⟩,
      _, rfl, rfl⟩

/-- (c) Right after a reboot `init` has not recorded the new TPM boot:
nothing in the journal is of it and nothing is mounted, so every command
refuses and `init` can only record a boot event, never take the record
as this boot's. -/
theorem reboot_stale {s : Sys B R D} (h : Reachable digest shirudo s) (b : B)
    (hb : b ∉ s.w.seen) (f : Nat → List D) (idx : Nat) (img : R) :
    Stale (afterReboot s.w b f idx img) ∧
      (afterReboot s.w b f idx img).mounted = none ∧
      (∀ e ∈ s.w.events, e.boot ≠ b) ∧
      check digest (afterReboot s.w b f idx img) ≠ .ok := by
  obtain ⟨hg, -, -⟩ := inv_reachable h
  have hst : Stale (afterReboot s.w b f idx img) := by
    intro r q hs hrb
    have hr := hg.state_seen r q hs
    rw [show r.boot = b from hrb] at hr
    exact hb hr
  exact ⟨hst, rfl, fun e he heb => hb (heb ▸ hg.events_seen e he),
      stale_refuses hst⟩

/-- (c) The reboot is the recovery. From every state any sequence of
commands, interruptions and boots reaches, pending, drifted or not, a
reboot and an `init` that nothing interrupts select the config
`boot_target()` takes, the staged one or the record's, record a boot
event of the new TPM boot for it, extend the PCR with that event alone
and complete, and every command then runs with that config. -/
theorem reboot_recovers {s : Sys B R D} (h : Reachable digest shirudo s) (b : B)
    (hb : b ∉ s.w.seen) (f : Nat → List D) (idx : Nat) (img : R) :
    ∃ s', Star (StepIn digest shirudo) ⟨afterReboot s.w b f idx img, .idle⟩ s' ∧
      s'.proc = .idle ∧ Admits digest s'.w ∧
      s'.w.mounted = some (selected (afterReboot s.w b f idx img)) ∧
      ∃ e, s'.w.state = some ⟨e, false⟩ ∧ e.kind = .boot ∧ e.boot = b ∧
        e.root = selected (afterReboot s.w b f idx img) ∧ e.initial = f idx ∧
        s'.w.pcr idx = digest .boot e.root :: f idx := by
  obtain ⟨hg, -, -⟩ := inv_reachable h
  obtain ⟨last, x, hscan, hnone, hnp, hpend⟩ := hg.journal
  have hfol : ∀ t,
      Follows last (newEvent (afterReboot s.w b f idx img) .boot t last) := by
    intro t
    cases last with
    | none => exact ⟨rfl, rfl⟩
    | some p =>
      have hne : p.boot ≠ b := fun he =>
        hb (he ▸ hg.events_seen p (scan_last hscan).1)
      exact ⟨rfl, fun he => absurd he hne, fun _ => rfl⟩
  have hdone : ∀ t, Star (StepIn digest shirudo)
      ⟨afterReboot s.w b f idx img, .starting .boot t last⟩
      ⟨booted digest (afterReboot s.w b f idx img) t last, .idle⟩ :=
    fun t => boot_run _ t last x hscan (hfol t)
  have hstart : StepIn digest shirudo ⟨afterReboot s.w b f idx img, .idle⟩
      ⟨afterReboot s.w b f idx img,
        .starting .boot (selected (afterReboot s.w b f idx img)) last⟩ := by
    cases hs : s.w.state with
    | none =>
      obtain ⟨hev, ht⟩ := hnone hs
      have hl : last = none := by
        rw [hev] at hscan
        simp [scan] at hscan
        exact hscan.1.symm
      subst hl
      have hsel : selected (afterReboot s.w b f idx img) = img := by
        simp [selected, afterReboot, hs]
      rw [hsel]
      exact StepIn.initFirst _ x hs hscan ht
    | some rec =>
      obtain ⟨r, q⟩ := rec
      have hsel : selected (afterReboot s.w b f idx img) =
          bootTarget (afterReboot s.w b f idx img) r := by
        simp [selected, afterReboot, hs]
      rw [hsel]
      have hne : r.boot ≠ b := fun he => by
        have hr := hg.state_seen r q hs
        rw [he] at hr
        exact hb hr
      refine StepIn.initNew (afterReboot s.w b f idx img) r q last x hs hne
        hscan ?_ ?_
      · intro ht
        cases q with
        | true => rfl
        | false =>
          exact absurd (show s.w.torn = true from ht)
            (by rw [(hnp r hs).2]; simp)
      · cases q with
        | true =>
          rcases hpend r hs with hl | hl
          · exact Or.inl hl
          · exact Or.inr ⟨rfl, hl⟩
        | false => exact Or.inl (hnp r hs).1
  refine ⟨_, Star.trans (Star.refl _ |>.tail hstart) (hdone _), rfl,
    booted_admits _ _ last x hscan (hfol _), rfl, _, rfl, rfl, rfl, rfl, rfl,
    extendAt_self _ _ _⟩

/-- (c) A startup completes only with a check of this TPM boot that found
the selected config's boot event last in the journal and the PCR holding
exactly that event over the value it started from, the selection pending
until then and that config mounted. This holds from any journal, however
corrupt or forged, any PCR values, and on root's TPM. -/
theorem boot_completion {w0 : World B R D} {s s' : Sys B R D} {sel : R}
    {r : Event B R D} (hrun : Star (Step digest rootTpm) ⟨w0, .idle⟩ s)
    (hs : s.proc = .checking (some sel)) (hstep : StepIn digest rootTpm s s')
    (hs' : s'.proc = .marking r (some sel)) :
    r.kind = .boot ∧ r.root = sel ∧ r.boot = s.w.boot ∧
      s.w.state = some ⟨r, true⟩ ∧ s.w.mounted = some sel ∧ s.w.torn = false ∧
      scan digest s.w.events = some (some r, digest .boot sel :: r.initial) ∧
      s.w.pcr r.pcr = digest .boot sel :: r.initial := by
  have hb := baseW_star (s := ⟨w0, .idle⟩) trivial hrun
  cases hstep
  case check w sel' r' q hst hc =>
    cases hs
    cases hs'
    obtain ⟨e, h1, h3, h4, -⟩ := hb
    rw [h1] at hst
    cases hst
    obtain ⟨hk, hroot⟩ := h4 sel rfl
    obtain ⟨x, hx, ht, hbo, hp⟩ := checkRecord_ok.1 hc
    obtain ⟨-, run, hrun'⟩ := scan_last hx
    have hxv : x = digest .boot sel :: r.initial := by
      rw [hrun', ← hroot]
      simp [fold, hk]
    rw [hxv] at hx hp
    exact ⟨hk, hroot, hbo.symm, h1, by rw [h3, hroot], ht, hx, hp⟩
  case outsider w π i d =>
    simp only at hs hs'
    rw [hs] at hs'
    cases hs'
  all_goals first
    | (simp only at hs'; cases hs')
    | (simp only at hs; cases hs)
    | (simp [rootTpm] at *)

/-- (e) A pending record becomes a completed one only through
`complete()`'s save after its `check_record()`, and a boot event's only
through `init`'s, which `image_boot_complete()` starts once the upatch
restore and the register binding have succeeded. From any journal, on
root's TPM. -/
theorem completion_by_complete {w0 : World B R D} {s s' : Sys B R D}
    {r r' : Event B R D} (hrun : Star (Step digest rootTpm) ⟨w0, .idle⟩ s)
    (hstep : StepIn digest rootTpm s s')
    (hs : s.w.state = some ⟨r, true⟩) (hs' : s'.w.state = some ⟨r', false⟩) :
    r' = r ∧ ∃ sel, s.proc = .marking r sel ∧
      (r.kind = .boot ↔ sel = some r.root) := by
  have hb := baseW_star (s := ⟨w0, .idle⟩) trivial hrun
  cases hstep
  case mark w r0 sel =>
    obtain ⟨h1, -, h4, h4', -⟩ := hb
    simp only at hs hs'
    rw [h1] at hs
    cases hs
    cases hs'
    refine ⟨rfl, sel, rfl, ⟨fun hk => ?_, fun hsel => (h4 _ hsel).1⟩⟩
    cases sel with
    | none => rw [h4' rfl] at hk; cases hk
    | some x => rw [(h4 x rfl).2]
  case save => simp only at hs'; cases hs'
  case restore => simp only at hs'; cases hs'
  case recover _ hv _ _ _ => simp [rootTpm] at hv
  all_goals (simp only at hs hs'; rw [hs] at hs'; cases hs')

end Boot

/-! ### The theorems fail for code that retries or recovers

Each variant below is the model with one more step: a retry, a recovery,
or root's TPM. A trace reaches a state that the theorem the variant
breaks rules out for shirudo on a calm TPM. -/

section Variants

variable {B R D : Type} [DecidableEq B] [DecidableEq R] [DecidableEq D]
variable {digest : Kind → R → D}

theorem Star.lift {v : Variant} {a b : Sys B R D}
    (h : Star (StepIn digest v) a b) :
    Star (Step digest v) a b :=
  Star.mono (fun _ _ h => Step.inBoot h) h

/-- A fresh target's first `init`, with `config.image` `img`. -/
theorem first_boot {v : Variant} (b : B) (f : Nat → List D) (idx : Nat)
    (img : R) : Star (StepIn digest v) ⟨fresh b f idx img, .idle⟩
      ⟨booted digest (fresh b f idx img) img none, .idle⟩ :=
  ((Star.refl _).tail (StepIn.initFirst _ [] rfl rfl rfl)).trans
    (boot_run _ img none [] rfl ⟨rfl, rfl⟩)

theorem first_boot_admits (b : B) (f : Nat → List D) (idx : Nat) (img : R) :
    Admits digest (booted digest (fresh b f idx img) img none) :=
  booted_admits _ img none [] rfl ⟨rfl, rfl⟩

omit [DecidableEq B] [DecidableEq R] [DecidableEq D] in
theorem follows_update {w : World B R D} {r : Event B R D} (t : R)
    (hb : r.boot = w.boot) (hp : r.pcr = w.cfgPcr) :
    Follows (some r) (newEvent w .update t (some r)) :=
  ⟨rfl, fun _ => ⟨rfl, hp, rfl⟩, fun hne => absurd hb hne⟩

/-- `image update` to its pending record, the extension next. -/
theorem update_saved {v : Variant} (w : World B R D) (r : Event B R D) (t : R)
    (hs : w.state = some ⟨r, false⟩) (hc : check digest w = .ok)
    (hm : w.mounted = some r.root) (hp : r.pcr = w.cfgPcr) (ht : t ≠ r.root) :
    Star (StepIn digest v) ⟨w, .idle⟩
      ⟨{ w with state := some ⟨newEvent w .update t (some r), true⟩ },
        .extending (newEvent w .update t (some r)) (w.pcr w.cfgPcr)⟩ := by
  have hb : r.boot = w.boot := by
    obtain ⟨r', hs', hr⟩ := check_ok.1 hc
    rw [hs] at hs'
    cases hs'
    obtain ⟨x, -, -, hbo, -⟩ := checkRecord_ok.1 hr
    exact hbo.symm
  exact (((Star.refl _).tail (StepIn.startUpdate w t r hs hc hm hp ht)).tail
    (StepIn.read _ _ _ _ (follows_update t hb hp))).tail (StepIn.save _ _ _)

/-- The first boot's record. -/
abbrev bootA (b : B) (f : Nat → List D) (idx : Nat) (A : R) : Event B R D :=
  newEvent (fresh b f idx A) .boot A none

/-- The target after its first boot with config `A`. -/
abbrev worldA (dg : Kind → R → D) (b : B) (f : Nat → List D) (idx : Nat)
    (A : R) : World B R D :=
  booted dg (fresh b f idx A) A none

/-- The update to config `B'` after that boot. -/
abbrev updB (dg : Kind → R → D) (b : B) (f : Nat → List D) (idx : Nat)
    (A B' : R) : Event B R D :=
  newEvent (worldA dg b f idx A) .update B' (some (bootA b f idx A))

/-- The first boot, then `image update` to `B'` to its pending record. -/
theorem boot_then_update_saved {v : Variant} (b : B) (f : Nat → List D)
    (idx : Nat) (A B' : R) (hAB : B' ≠ A) :
    Star (StepIn digest v) ⟨fresh b f idx A, .idle⟩
      ⟨{ worldA digest b f idx A with
          state := some ⟨updB digest b f idx A B', true⟩ },
        .extending (updB digest b f idx A B')
          ((worldA digest b f idx A).pcr idx)⟩ :=
  (first_boot b f idx A).trans
    (update_saved _ (bootA b f idx A) B' rfl
        (first_boot_admits b f idx A).1 rfl rfl hAB)

/-- Variant `retry`: an extension whose answer was lost is sent again,
and `extends_once` fails: one activation, two extensions in one TPM boot.
The trace: a fresh target's `init` saves its pending boot event, sends
the extension, gets no answer, and sends it again. -/
theorem retry_extends_twice (b : B) (f : Nat → List D) (idx : Nat) (img : R) :
    ∃ s : Sys B R D, Reachable digest { retry := true } s ∧ ¬ s.w.sent.Nodup :=
  ⟨_, ⟨b, f, idx, img, Star.lift
      (((((Star.refl _).tail (StepIn.initFirst _ [] rfl rfl rfl)).tail
        (StepIn.read _ _ _ _ ⟨rfl, rfl⟩)).tail (StepIn.save _ _ _)).tail
        (StepIn.retry _ _ _ true rfl) |>.tail (StepIn.extendLost _ _ _))⟩,
    fun hnd => (List.nodup_cons.1 hnd).1 List.mem_cons_self⟩

/-- Variant `recover`: a command finds the pending activation's extension
in the PCR and records it complete, and `refusal_persists` fails: after
an interruption commands run again within the TPM boot. The trace: the
first boot with config `A`; `image update` to `B'` extends the PCR,
appends its event and mounts `B'`, then fails before `complete()`; the
recovery records `B'` complete. -/
theorem recover_admits_within_boot (b : B) (f : Nat → List D) (idx : Nat)
    (A B' : R) (hAB : B' ≠ A) :
    ∃ s s' : Sys B R D, Reachable digest { recover := true } s ∧
      s.proc = .idle ∧ PendingHere s.w ∧ ¬ Admits digest s.w ∧
      Star (StepIn digest { recover := true }) s s' ∧ Admits digest s'.w := by
  have hscanA : scan digest (worldA digest b f idx A).events =
      some (some (bootA b f idx A), fold digest (bootA b f idx A) []) :=
    scan_cons.2 ⟨none, [], rfl, ⟨rfl, rfl⟩, rfl⟩
  have hfB : Follows (some (bootA b f idx A)) (updB digest b f idx A B') :=
    follows_update B' rfl rfl
  have hp1 : extendAt (worldA digest b f idx A).pcr idx (digest .update B')
      idx = digest .update B' :: (worldA digest b f idx A).pcr idx :=
    extendAt_self _ _ _
  have hp2 : extendAt (worldA digest b f idx A).pcr idx (digest .update B')
      idx =
      digest .update B' :: digest .boot A :: f idx := by
    simp [worldA, booted, fresh, extendAt]
  let run :=
    ((((boot_then_update_saved (digest := digest) (v := { recover := true })
        b f idx A B' hAB).tail (StepIn.extend _ _ _)).tail
      (StepIn.readback _ _ _ rfl hp1)).tail
      (StepIn.append _ _ _ _ (fun h => by cases h) hscanA hfB)).tail
      (StepIn.activateUpdate _ _ rfl) |>.tail (StepIn.crash _ _)
  refine ⟨_, _, ⟨b, f, idx, A, Star.lift run⟩, rfl, ⟨_, rfl, rfl⟩,
    fun ha => absurd ha.1 (by rw [pendingHere_refuses ⟨_, rfl, rfl⟩]; simp),
    (Star.refl _).tail (StepIn.recover _ (updB digest b f idx A B') rfl rfl rfl
      (checkRecord_ok.2
          ⟨_, scan_cons.2 ⟨_, _, hscanA, hfB, rfl⟩, rfl, rfl, hp2⟩)), ?_⟩
  exact ⟨check_ok.2 ⟨_, rfl, checkRecord_ok.2
    ⟨_, scan_cons.2 ⟨_, _, hscanA, hfB, rfl⟩, rfl, rfl, hp2⟩⟩, _, rfl, rfl⟩

/-- Root's TPM: a `TPM2_Clear`, which sets the reset count to another
value and keeps the PCRs, lands while `image update` runs, between its
pending record and its extension, and `extends_once` fails. The extension
lands in the new TPM boot while the record names the old one; the update
refuses at its read back; `init` run by hand then takes the record as an
earlier boot's and extends the PCR a second time for the same activation
in that TPM boot, on top of the first. -/
theorem clear_in_flight_extends_twice (b0 b1 : B) (hb : b1 ≠ b0)
    (f : Nat → List D) (idx : Nat) (A B' : R) (hAB : B' ≠ A) :
    ∃ s : Sys B R D, Reachable digest rootTpm s ∧
      ¬ s.w.sent.Nodup ∧ s.w.boot = b1 ∧
      s.w.pcr idx =
        [digest .boot B', digest .update B', digest .boot A] ++ f idx := by
  have hscanA : scan digest (worldA digest b0 f idx A).events =
      some (some (bootA b0 f idx A), fold digest (bootA b0 f idx A) []) :=
    scan_cons.2 ⟨none, [], rfl, ⟨rfl, rfl⟩, rfl⟩
  have hfB : Follows (some (bootA b0 f idx A)) (updB digest b0 f idx A B') :=
    follows_update B' rfl rfl
  have hseen : b1 ∉ (worldA digest b0 f idx A).seen := by
    simp [worldA, booted, fresh, hb]
  let saved := boot_then_update_saved (digest := digest)
    (v := rootTpm)
    b0 f idx A B' hAB
  let w1 : World B R D :=
    { worldA digest b0 f idx A with
      state := some ⟨updB digest b0 f idx A B', true⟩ }
  let w2 : World B R D :=
    { w1 with boot := b1, pcr := w1.pcr, seen := b1 :: w1.seen }
  have hrestart : Step digest rootTpm
      ⟨w1, .extending (updB digest b0 f idx A B')
          ((worldA digest b0 f idx A).pcr idx)⟩
      ⟨w2, .extending (updB digest b0 f idx A B')
          ((worldA digest b0 f idx A).pcr idx)⟩ :=
    Step.reset _ b1 true f (Or.inr rfl) (Or.inl hseen)
  let w3 : World B R D :=
    { w2 with pcr := extendAt w2.pcr idx (digest .update B'),
              sent := (b1, (updB digest b0 f idx A B').seq) :: w2.sent }
  have hstale : (updB digest b0 f idx A B').boot ≠ w3.boot := fun h => hb h.symm
  let eB2 := newEvent w3 .boot B' (some (bootA b0 f idx A))
  have hfB2 : Follows (some (bootA b0 f idx A)) eB2 :=
    ⟨rfl, fun h => absurd h.symm hb, fun _ => rfl⟩
  have hinit : Star (StepIn digest rootTpm)
      ⟨w2, .extending (updB digest b0 f idx A B')
          ((worldA digest b0 f idx A).pcr idx)⟩
      ⟨{ w3 with
          state := some ⟨eB2, true⟩,
          pcr := extendAt w3.pcr idx (digest .boot B'),
          sent := (b1, eB2.seq) :: w3.sent }, .readback eB2 (w3.pcr idx)⟩ :=
    ((((((Star.refl _).tail (StepIn.extend _ _ _)).tail (StepIn.crash _ _)).tail
      (StepIn.initNew _ _ true _ _ rfl hstale hscanA (fun _ => rfl)
        (Or.inr ⟨rfl, hfB⟩))).tail (StepIn.read _ _ _ _ hfB2)).tail
      (StepIn.save _ _ _)).tail (StepIn.extend _ _ _)
  refine ⟨_,
      ⟨b0, f, idx, A, ((Star.lift saved).tail hrestart).trans
          (Star.lift hinit)⟩,
    fun hnd => (List.nodup_cons.1 hnd).1 List.mem_cons_self, rfl, ?_⟩
  simp [w3, w2, w1, worldA, booted, fresh, extendAt]

/-- (a) A pending activation stays pending until the TPM's reset count
changes, a reboot's: whatever commands run, crash or extend the PCR, and
however often the TPM resumes or restarts, at any point, `init` takes
nothing, the record stays as it is and every command but `status` and
`image status` refuses. -/
theorem pending_until_reboot {v : Variant} (hv : v.recover = false)
    {s s' : Sys B R D} (hidle : s.proc = .idle) (hp : PendingHere s.w)
    (hrun : Star (SameBoot digest v) s s') :
    s'.proc = .idle ∧ s'.w.state = s.w.state ∧ s'.w.boot = s.w.boot ∧
      ¬ Admits digest s'.w := by
  obtain ⟨r0, hs0, hb0⟩ := hp
  have hkeep : ∀ {a : Sys B R D}, a.proc = .idle → a.w.state = s.w.state →
      a.w.boot = s.w.boot → ∀ {c : Sys B R D}, SameBoot digest v a c →
      c.proc = .idle ∧ c.w.state = s.w.state ∧ c.w.boot = s.w.boot := by
    intro a hi ha hb c h
    have hs : a.w.state = some ⟨r0, true⟩ := ha.trans hs0
    cases h with
    | restart keep f _ _ => exact ⟨hi, ha, hb⟩
    | inBoot h =>
      cases h with
      | crash => exact ⟨rfl, ha, hb⟩
      | outsider w π i d => exact ⟨hi, ha, hb⟩
      | startUpdate _ _ _ h1 => simp only at hs; rw [hs] at h1; cases h1
      | initSame _ _ h1 => simp only at hs; rw [hs] at h1; cases h1
      | initFirst _ _ h1 => simp only at hs; rw [hs] at h1; cases h1
      | initNew w r q last x h1 h2 =>
        simp only at hs hb
        rw [hs] at h1
        cases h1
        exact absurd (hb0.trans hb.symm) h2
      | stage _ _ _ h1 => simp only at hs; rw [hs] at h1; cases h1
      | unstage _ _ h1 => simp only at hs; rw [hs] at h1; cases h1
      | recover _ _ hr => rw [hv] at hr; cases hr
      | _ => cases hi
  have hall : s'.proc = .idle ∧ s'.w.state = s.w.state ∧
      s'.w.boot = s.w.boot := by
    induction hrun with
    | refl => exact ⟨hidle, rfl, rfl⟩
    | tail _ hstep ih => exact hkeep ih.1 ih.2.1 ih.2.2 hstep
  refine ⟨hall.1, hall.2.1, hall.2.2, fun ha => ?_⟩
  obtain ⟨r, hr, -⟩ := check_ok.1 ha.1
  rw [hall.2.1, hs0] at hr
  cases hr

/-- A TPM Resume, as from suspend to RAM, keeps the config PCR and the TPM
boot, so an interrupted activation stays pending until a reboot. The
trace: the first boot with config `A`; `image update` to `B'` extends the
PCR and gets no answer, leaving `B'` pending and the PCR holding its
update event. Then however the TPM resumes or restarts, `init` records
nothing and no command runs, until the reset count changes. -/
theorem resume_keeps_pending (b0 : B) (f : Nat → List D) (idx : Nat)
    (A B' : R) (hAB : B' ≠ A) :
    ∃ s1 : Sys B R D, Reachable digest shirudo s1 ∧ s1.proc = .idle ∧
      PendingHere s1.w ∧
      s1.w.pcr idx = [digest .update B', digest .boot A] ++ f idx ∧
      ∀ s2, Star (SameBoot digest rootTpm) s1 s2 →
        s2.w.state = s1.w.state ∧ ¬ Admits digest s2.w := by
  let run := ((boot_then_update_saved (digest := digest) (v := shirudo)
      b0 f idx A B' hAB).tail (StepIn.extend _ _ _)).tail (StepIn.crash _ _)
  let w1 : World B R D :=
    { worldA digest b0 f idx A with
      state := some ⟨updB digest b0 f idx A B', true⟩,
      pcr := extendAt (worldA digest b0 f idx A).pcr idx (digest .update B'),
      sent := (b0, (updB digest b0 f idx A B').seq) ::
        (worldA digest b0 f idx A).sent }
  have hpcr : w1.pcr idx = [digest .update B', digest .boot A] ++ f idx := by
    simp [w1, worldA, booted, fresh, extendAt]
  refine ⟨⟨w1, .idle⟩, ⟨b0, f, idx, A, Star.lift run⟩, rfl, ⟨_, rfl, rfl⟩,
    hpcr, fun s2 h => ?_⟩
  · obtain ⟨-, hs, -, hna⟩ := pending_until_reboot (v := rootTpm) rfl rfl
      ⟨_, rfl, rfl⟩ h
    exact ⟨hs, hna⟩

/-- `image stage` and a reboot: `init` activates the staged config. The
trace: the first boot with config `A`, `image stage` of `B'`, a reboot;
`init` takes `B'`, records its boot event and completes, and commands run
with `B'`. -/
theorem stage_then_reboot (b0 b1 : B) (hb : b1 ≠ b0) (f f' : Nat → List D)
    (idx : Nat) (A B' : R) (hAB : B' ≠ A) :
    ∃ s s' : Sys B R D, Reachable digest shirudo s ∧
      s.w.staged = some { bootA b0 f idx A with root := B' } ∧
      Star (StepIn digest shirudo) ⟨afterReboot s.w b1 f' idx A, .idle⟩ s' ∧
      s'.proc = .idle ∧ Admits digest s'.w ∧ s'.w.mounted = some B' := by
  have ha := first_boot_admits (digest := digest) b0 f idx A
  let w1 : World B R D :=
    { worldA digest b0 f idx A with
      staged := some { bootA b0 f idx A with root := B' } }
  have hstage : StepIn digest shirudo ⟨worldA digest b0 f idx A, .idle⟩
      ⟨w1, .idle⟩ :=
    StepIn.stage _ B' (bootA b0 f idx A) rfl ha.1 rfl
  have hreach : Reachable digest shirudo ⟨w1, .idle⟩ :=
    ⟨b0, f, idx, A, (Star.lift (first_boot b0 f idx A)).tail
      (Step.inBoot hstage)⟩
  have hseen : b1 ∉ w1.seen := by
    simp [w1, worldA, booted, fresh, hb]
  have hc : ({ bootA b0 f idx A with root := B' } : Event B R D).boot ≠ b1 ∧
      B' ≠ (bootA b0 f idx A).root ∧
      (bootA b0 f idx A).seq = (bootA b0 f idx A).seq ∧
      (bootA b0 f idx A).boot = (bootA b0 f idx A).boot :=
    ⟨Ne.symm hb, hAB, rfl, rfl⟩
  have hsel : selected (afterReboot w1 b1 f' idx A) = B' := by
    show (if ({ bootA b0 f idx A with root := B' } : Event B R D).boot ≠ b1 ∧
        B' ≠ (bootA b0 f idx A).root ∧
        (bootA b0 f idx A).seq = (bootA b0 f idx A).seq ∧
        (bootA b0 f idx A).boot = (bootA b0 f idx A).boot
      then B' else (bootA b0 f idx A).root) = B'
    split
    · rfl
    · next hn => exact absurd hc hn
  obtain ⟨s', hrun, hidle, hadm, hmnt, -⟩ :=
    reboot_recovers hreach b1 hseen f' idx A
  exact ⟨⟨w1, .idle⟩, s', hreach, rfl, hrun, hidle, hadm, by rw [hmnt, hsel]⟩

end Variants

end Shirudo.ConfigActivation
