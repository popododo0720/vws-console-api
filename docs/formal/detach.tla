------------------------------- MODULE detach -------------------------------
(***************************************************************************)
(* The DetachVolume recovery path of the gRPC backend (#343).              *)
(*                                                                         *)
(* One instance (vws-compute) holds the attachment in spec.volumes and the *)
(* replay state in labels: a detach record vws-detach-<vol> naming the     *)
(* request, and the saved operation id vws-dop-<vol>. console-api callers  *)
(* (internal/backend/grpcclient/ec2.go) read the instance, then write it   *)
(* back with an etag compare-and-swap and a request id compute replays.    *)
(*                                                                         *)
(* What one step is: every read (GetInstance) and every write              *)
(* (UpdateInstance) is its own step, because the code does them as         *)
(* separate RPCs. Compute applies one UpdateInstance atomically.           *)
(*                                                                         *)
(* Abstractions (see docs/formal/README.md):                               *)
(*  - A request is its client token; a token names one volume (TokVol).    *)
(*    A record's stamp is its token, so a resend of the same record is    *)
(*    the same bytes.                                                      *)
(*  - Time is the set expired: a token whose record is past               *)
(*    backend.ClientTokenExpired, and whose request id compute has        *)
(*    forgotten. With WithinWindow, no caller still holding the token     *)
(*    retries after it expires (#305 covers that case).                    *)
(*  - Labels are counted against Budget: user tags, records and op ids.    *)
(*    The fixed internal labels are left out, as labelReserve is.          *)
(*  - Records written before #303 (no stamp) and other instances           *)
(*    (findDetachReplay paging, a move to another instance) are not        *)
(*    modeled.                                                             *)
(*                                                                         *)
(* Fix* constants switch one fix of the real code off, to show that the   *)
(* invariant it guards can fail. The real design has every Fix* TRUE.      *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Callers,      \* concurrent DetachVolume calls (console-api requests)
    Tokens,       \* client tokens; callers may share one (a replay)
    Vols,         \* non-boot volumes attached to the instance
    InitTags,     \* user tags the instance may start with (any subset)
    TagKeys,      \* tags a concurrent CreateTags may add
    Budgets,      \* compute's label limit, scaled down from labelMax (64); one per run
    MaxReplays,   \* backend.MaxDetachReplays, scaled down from 4
    MaxRestarts,  \* console-api restarts over the whole run
    MaxReattach,  \* AttachVolume calls that put a detached volume back
    None,
    WithinWindow,      \* retries arrive within backend.ClientTokenWindow
    FixPendingReserve, \* every label write reserves pending op ids (#327, d8d7066)
    FixHold,           \* prune keeps expired records while a recovery is pending (#319)
    FixEtagCAS,        \* every instance write carries the etag it read
    FixOpBinding,      \* a saved op id is bound to its request and dropped by a new record (#213, #302)
    FixPruneExpiredOnly, \* prune drops expired records only (#303)
    FixPendingExpires, \* an expired record no longer holds (pendingDetachOps, #322)
    FixEtagReread, \* an etag mismatch rereads the instance (DetachVolume's loop)
    FixResendRecover \* a write refused as a mismatch next to this request's record saves an op (#352)

ASSUME Budgets \subseteq Nat /\ MaxReplays \in Nat /\ MaxRestarts \in Nat /\ MaxReattach \in Nat

Live == {"read", "write", "rread", "recover", "pread", "pwrite"}
Results == {"ok", "exhausted", "noroom", "notinuse", "mismatch", "params", "capacity", "lost"}

VARIABLES
    tokOf,     \* caller -> token (chosen at Init, fixed)
    volOf,     \* token -> volume (chosen at Init, fixed)
    Budget,    \* the label limit of this run (chosen at Init from Budgets, fixed)
    inst,      \* [spec, rec, dop, tags]: the instance as compute stores it
    etag,      \* the instance etag (a write counter)
    expired,   \* tokens past the client-token window
    reqStore,  \* token -> the payload compute stored for that request id, or None
    pc, snap, pay, result, retop,  \* caller state
    tpc, tsnap, tpay,              \* CreateTags state, per tag key
    acked,     \* tags whose CreateTags compute applied (history)
    accepted,  \* tokens whose detach write compute applied (history)
    applied,   \* token -> times compute removed its volume for it (history)
    heldPruned,\* an expired record was pruned while a recovery was pending (history)
    liveDropped,\* a write removed a record a running caller's token owns (history)
    restarts, reattaches

vars == <<tokOf, volOf, Budget, inst, etag, expired, reqStore, pc, snap, pay, result, retop,
          tpc, tsnap, tpay, acked, accepted, applied, heldPruned, liveDropped, restarts, reattaches>>

-----------------------------------------------------------------------------
\* Labels of an instance image.

Recs(i) == {v \in Vols : i.rec[v] # None}
Ops(i)  == {v \in Vols : i.dop[v] # None}
Count(i) == Cardinality(Recs(i)) + Cardinality(Ops(i)) + Cardinality(i.tags)

\* pendingDetachOps: records within the window with no saved op id.
Pending(i) ==
    Cardinality({v \in Recs(i) : (FixPendingExpires => i.rec[v] \notin expired) /\ i.dop[v] = None})

\* detachRecoveryPending.
Hold(i) == FixHold /\ Pending(i) > 0

\* pruneDetachRecords: an expired record goes, with its op id, unless a
\* recovery is pending; an op id with no record goes.
Drop(i, v) == IF FixPruneExpiredOnly
              THEN i.rec[v] \in expired /\ ~Hold(i)
              ELSE (i.rec[v] \in expired /\ ~Hold(i)) \/ i.dop[v] = None
Prune(i) ==
    LET kept == {v \in Recs(i) : ~Drop(i, v)}
    IN [i EXCEPT !.rec = [v \in Vols |-> IF v \in kept THEN i.rec[v] ELSE None],
                 !.dop = [v \in Vols |-> IF v \in kept THEN i.dop[v] ELSE None]]

\* detachRecordsInWindow, without the record of skip.
InWindow(i, skip) ==
    LET p == Prune(i) IN
    Cardinality({v \in Recs(p) \ {skip} : p.rec[v] \notin expired})

\* instanceUpdateLabels: the capacity check of a new label write. Before
\* d8d7066 only the detach itself left room for its own op id.
Fits(i, isDetach) ==
    Count(i) + (IF FixPendingReserve THEN Pending(i)
                ELSE IF isDetach THEN 1 ELSE 0) <= Budget

\* An expired record pruned by a write while a recovery was pending.
PrunesHeld(before, after) ==
    Pending(before) > 0 /\
    \E v \in Recs(before) : before.rec[v] \in expired /\ after.rec[v] = None

\* A write that removes, without replacing, a record whose token a running
\* caller still holds (a later detach of the volume replaces it instead).
DropsLive(before, after) ==
    \E v \in Recs(before) :
        /\ after.rec[v] = None
        /\ \E c \in Callers : tokOf[c] = before.rec[v] /\ pc[c] \in Live

\* vws-compute UpdateInstance: request id replay, then etag, then the label
\* limit. A write with no replayable request id passes None.
Compute(t, e, p) ==
    IF t # None /\ reqStore[t] # None
    THEN IF reqStore[t] = p THEN "replay" ELSE "mismatch"
    ELSE IF FixEtagCAS /\ e # etag THEN "etag"
    ELSE IF Count(p) > Budget THEN "capacity"
    ELSE "applied"

\* Apply a write; t is the detach token it removes a volume for, or None.
Apply(p, t) ==
    /\ inst' = p
    /\ etag' = etag + 1
    /\ heldPruned' = (heldPruned \/ PrunesHeld(inst, p))
    /\ liveDropped' = (liveDropped \/ DropsLive(inst, p))

-----------------------------------------------------------------------------

Init ==
    /\ tokOf \in [Callers -> Tokens]
    /\ volOf \in [Tokens -> Vols]
    /\ Budget \in Budgets
    /\ \E start \in SUBSET InitTags :
           inst = [spec |-> Vols, rec |-> [v \in Vols |-> None],
                   dop |-> [v \in Vols |-> None], tags |-> start]
    /\ etag = 0
    /\ expired = {}
    /\ reqStore = [t \in Tokens |-> None]
    /\ pc = [c \in Callers |-> "read"]
    /\ snap = [c \in Callers |-> 0]
    /\ pay = [c \in Callers |-> None]
    /\ result = [c \in Callers |-> None]
    /\ retop = [c \in Callers |-> None]
    /\ tpc = [k \in TagKeys |-> "read"]
    /\ tsnap = [k \in TagKeys |-> 0]
    /\ tpay = [k \in TagKeys |-> None]
    /\ acked = {}
    /\ accepted = {}
    /\ applied = [t \in Tokens |-> 0]
    /\ heldPruned = FALSE
    /\ liveDropped = FALSE
    /\ restarts = 0
    /\ reattaches = 0

Finish(c, r, op) ==
    /\ pc' = [pc EXCEPT ![c] = "done"]
    /\ result' = [result EXCEPT ![c] = r]
    /\ retop' = [retop EXCEPT ![c] = op]

\* The saved op id answers this request (detachReplay.opMatch).
OpSaved(i, v, t) == IF FixOpBinding THEN i.dop[v] = t ELSE i.dop[v] # None

\* detachOnce and the first half of writeDetach: one GetInstance.
Read(c) ==
    LET t == tokOf[c]
        v == volOf[t]
        i == inst
    IN
    /\ pc[c] = "read"
    /\ snap' = [snap EXCEPT ![c] = etag]
    /\ CASE i.rec[v] = t /\ OpSaved(i, v, t) ->
              \* opSaved: acceptDetachReplay
              Finish(c, "ok", i.dop[v]) /\ UNCHANGED pay
         [] i.rec[v] = t /\ i.dop[v] # None ->
              \* opOtherParams
              Finish(c, "params", None) /\ UNCHANGED pay
         [] i.rec[v] = t /\ v \notin i.spec ->
              \* opUnknown, not bound: writeDetach(drop=false) resends the
              \* stored records unpruned (storedDetachRecords).
              /\ pay' = [pay EXCEPT ![c] = [i EXCEPT !.dop[v] = None]]
              /\ pc' = [pc EXCEPT ![c] = "write"]
              /\ UNCHANGED <<result, retop>>
         [] v \in i.spec ->
              \* bound: writeDetach(drop=true), a new record.
              IF InWindow(i, v) >= MaxReplays
              THEN Finish(c, "exhausted", None) /\ UNCHANGED pay
              ELSE LET q == Prune(i)
                       p == [q EXCEPT !.spec = @ \ {v}, !.rec[v] = t,
                                      !.dop[v] = IF FixOpBinding THEN None ELSE @]
                   IN IF Fits(p, TRUE)
                      THEN /\ pay' = [pay EXCEPT ![c] = p]
                           /\ pc' = [pc EXCEPT ![c] = "write"]
                           /\ UNCHANGED <<result, retop>>
                      ELSE Finish(c, "noroom", None) /\ UNCHANGED pay
         [] OTHER ->
              \* findDetachReplay finds nothing: VolumeNotInUse.
              Finish(c, "notinuse", None) /\ UNCHANGED pay
    /\ UNCHANGED <<tokOf, volOf, Budget, inst, etag, expired, reqStore, tpc, tsnap, tpay,
                   acked, accepted, applied, heldPruned, liveDropped, restarts, reattaches>>

\* writeDetach: UpdateInstance with RequestId requestUUID(key, "detach").
Write(c) ==
    LET t == tokOf[c]
        v == volOf[t]
        p == pay[c]
        r == Compute(t, snap[c], p)
    IN
    /\ pc[c] = "write"
    /\ CASE r = "applied" ->
              /\ Apply(p, t)
              /\ reqStore' = [reqStore EXCEPT ![t] = p]
              /\ accepted' = accepted \cup {t}
              /\ applied' = [applied EXCEPT ![t] =
                                @ + (IF v \in inst.spec /\ v \notin p.spec THEN 1 ELSE 0)]
              /\ pc' = [pc EXCEPT ![c] = "pread"]
              /\ UNCHANGED <<result, retop>>
         [] r = "replay" ->
              /\ pc' = [pc EXCEPT ![c] = "pread"]
              /\ UNCHANGED <<inst, etag, heldPruned, liveDropped, reqStore, accepted, applied, result, retop>>
         [] r = "etag" ->
              \* etagMismatchError: DetachVolume rereads.
              /\ pc' = [pc EXCEPT ![c] = IF FixEtagReread THEN "read" ELSE "write"]
              /\ UNCHANGED <<inst, etag, heldPruned, liveDropped, reqStore, accepted, applied, result, retop>>
         [] r = "mismatch" /\ FixResendRecover ->
              \* IDEMPOTENCY_CONFLICT: writeDetach rereads the instance (RRead).
              /\ pc' = [pc EXCEPT ![c] = "rread"]
              /\ UNCHANGED <<inst, etag, heldPruned, liveDropped, reqStore, accepted, applied, result, retop>>
         [] OTHER ->
              /\ Finish(c, r, None)
              /\ UNCHANGED <<inst, etag, heldPruned, liveDropped, reqStore, accepted, applied>>
    /\ UNCHANGED <<tokOf, volOf, Budget, expired, snap, pay, tpc, tsnap, tpay, acked,
                   restarts, reattaches>>

\* writeDetach after IDEMPOTENCY_CONFLICT (#352): this request's record on
\* the instance proves its detach was applied, but compute cannot replay the
\* write, as the instance changed since. No record: the token was used with
\* other parameters.
RRead(c) ==
    LET t == tokOf[c]
        v == volOf[t]
    IN
    /\ pc[c] = "rread"
    /\ IF inst.rec[v] = t
       THEN /\ snap' = [snap EXCEPT ![c] = etag]
            /\ pay' = [pay EXCEPT ![c] = inst]
            /\ pc' = [pc EXCEPT ![c] = "recover"]
            /\ UNCHANGED <<result, retop>>
       ELSE Finish(c, "mismatch", None) /\ UNCHANGED <<snap, pay>>
    /\ UNCHANGED <<tokOf, volOf, Budget, inst, etag, expired, reqStore, tpc, tsnap, tpay,
                   acked, accepted, applied, heldPruned, liveDropped, restarts, reattaches>>

\* The instance as reread, under requestUUID(key, "detach-recover", etag):
\* its op ends when the instance reaches that spec, and is saved as this
\* detach's (PRead).
Recover(c) ==
    LET r == Compute(None, snap[c], pay[c]) IN
    /\ pc[c] = "recover"
    /\ CASE r = "applied" ->
              Apply(pay[c], None) /\ pc' = [pc EXCEPT ![c] = "pread"] /\ UNCHANGED <<result, retop>>
         [] r = "etag" ->
              /\ pc' = [pc EXCEPT ![c] = IF FixEtagReread THEN "read" ELSE "recover"]
              /\ UNCHANGED <<inst, etag, heldPruned, liveDropped, result, retop>>
         [] OTHER ->
              Finish(c, r, None) /\ UNCHANGED <<inst, etag, heldPruned, liveDropped>>
    /\ UNCHANGED <<tokOf, volOf, Budget, expired, reqStore, snap, pay, tpc, tsnap, tpay,
                   acked, accepted, applied, restarts, reattaches>>

\* persistDetachOp: GetInstance, then save the op id unless a later detach
\* owns the record.
PRead(c) ==
    LET t == tokOf[c]
        v == volOf[t]
    IN
    /\ pc[c] = "pread"
    /\ IF inst.dop[v] = t \/ inst.rec[v] # t
       THEN Finish(c, "ok", t) /\ UNCHANGED <<snap, pay>>
       ELSE /\ snap' = [snap EXCEPT ![c] = etag]
            /\ pay' = [pay EXCEPT ![c] = [inst EXCEPT !.dop[v] = t]]
            /\ pc' = [pc EXCEPT ![c] = "pwrite"]
            /\ UNCHANGED <<result, retop>>
    /\ UNCHANGED <<tokOf, volOf, Budget, inst, etag, expired, reqStore, tpc, tsnap, tpay,
                   acked, accepted, applied, heldPruned, liveDropped, restarts, reattaches>>

\* persistDetachOp's UpdateInstance: a fresh request id per etag and no
\* client-side capacity check (its label was reserved).
PWrite(c) ==
    LET r == Compute(None, snap[c], pay[c]) IN
    /\ pc[c] = "pwrite"
    /\ CASE r = "applied" -> Apply(pay[c], None) /\ Finish(c, "ok", tokOf[c])
         [] r = "etag" ->
              /\ pc' = [pc EXCEPT ![c] = "pread"]
              /\ UNCHANGED <<inst, etag, heldPruned, liveDropped, result, retop>>
         [] OTHER ->
              \* the detach happened, but its op id has no room: an error.
              Finish(c, "lost", None) /\ UNCHANGED <<inst, etag, heldPruned, liveDropped>>
    /\ UNCHANGED <<tokOf, volOf, Budget, expired, reqStore, snap, pay, tpc, tsnap, tpay,
                   acked, accepted, applied, restarts, reattaches>>

\* A console-api restart (or a lost response) at any step: the client
\* retries with the same token from the start.
Restart(c) ==
    /\ pc[c] \in Live
    /\ restarts < MaxRestarts
    /\ restarts' = restarts + 1
    /\ pc' = [pc EXCEPT ![c] = "read"]
    /\ UNCHANGED <<tokOf, volOf, Budget, inst, etag, expired, reqStore, snap, pay, result,
                   retop, tpc, tsnap, tpay, acked, accepted, applied, heldPruned, liveDropped,
                   reattaches>>

\* The client gives up; its record may stay pending until it expires.
Abandon(c) ==
    /\ pc[c] \in Live
    /\ pc' = [pc EXCEPT ![c] = "gone"]
    /\ UNCHANGED <<tokOf, volOf, Budget, inst, etag, expired, reqStore, snap, pay, result,
                   retop, tpc, tsnap, tpay, acked, accepted, applied, heldPruned, liveDropped,
                   restarts, reattaches>>

\* CreateTags on the instance (ec2.go CreateTags, instanceUpdateLabels).
TRead(k) ==
    LET p == [Prune(inst) EXCEPT !.tags = @ \cup {k}] IN
    /\ tpc[k] = "read"
    /\ tsnap' = [tsnap EXCEPT ![k] = etag]
    /\ IF Fits(p, FALSE)
       THEN tpay' = [tpay EXCEPT ![k] = p] /\ tpc' = [tpc EXCEPT ![k] = "write"]
       ELSE tpc' = [tpc EXCEPT ![k] = "refused"] /\ UNCHANGED tpay
    /\ UNCHANGED <<tokOf, volOf, Budget, inst, etag, expired, reqStore, pc, snap, pay, result,
                   retop, acked, accepted, applied, heldPruned, liveDropped, restarts, reattaches>>

TWrite(k) ==
    LET r == Compute(None, tsnap[k], tpay[k]) IN
    /\ tpc[k] = "write"
    /\ CASE r = "applied" ->
              /\ Apply(tpay[k], None)
              /\ acked' = acked \cup {k}
              /\ tpc' = [tpc EXCEPT ![k] = "done"]
         [] r = "etag" ->
              tpc' = [tpc EXCEPT ![k] = "read"] /\ UNCHANGED <<inst, etag, heldPruned, liveDropped, acked>>
         [] OTHER ->
              tpc' = [tpc EXCEPT ![k] = "capacity"] /\ UNCHANGED <<inst, etag, heldPruned, liveDropped, acked>>
    /\ UNCHANGED <<tokOf, volOf, Budget, expired, reqStore, pc, snap, pay, result, retop,
                   tsnap, tpay, accepted, applied, restarts, reattaches>>

\* AttachVolume puts a detached volume back (ec2.go AttachVolume,
\* instanceUpdateLabels). Its read-modify-write is one step here.
Reattach(v) ==
    LET p == [Prune(inst) EXCEPT !.spec = @ \cup {v}] IN
    /\ reattaches < MaxReattach
    /\ v \notin inst.spec
    /\ Fits(p, FALSE)
    /\ Apply(p, None)
    /\ reattaches' = reattaches + 1
    /\ UNCHANGED <<tokOf, volOf, Budget, expired, reqStore, pc, snap, pay, result, retop,
                   tpc, tsnap, tpay, acked, accepted, applied, restarts>>

\* The window passes for a token: its record expires
\* (backend.ClientTokenExpired) and compute forgets its request id.
Expire(t) ==
    /\ t \notin expired
    /\ reqStore[t] # None
    /\ WithinWindow => \A c \in Callers : tokOf[c] = t => pc[c] \notin Live
    /\ expired' = expired \cup {t}
    /\ reqStore' = [reqStore EXCEPT ![t] = None]
    /\ UNCHANGED <<tokOf, volOf, Budget, inst, etag, pc, snap, pay, result, retop, tpc, tsnap,
                   tpay, acked, accepted, applied, heldPruned, liveDropped, restarts, reattaches>>

Done ==
    /\ \A c \in Callers : pc[c] \notin Live
    /\ \A k \in TagKeys : tpc[k] \notin {"read", "write"}
    /\ UNCHANGED vars

Progress(c) == Read(c) \/ Write(c) \/ RRead(c) \/ Recover(c) \/ PRead(c) \/ PWrite(c)

Next ==
    \/ \E c \in Callers : Progress(c) \/ Restart(c) \/ Abandon(c)
    \/ \E k \in TagKeys : TRead(k) \/ TWrite(k)
    \/ \E v \in Vols : Reattach(v)
    \/ \E t \in Tokens : Expire(t)
    \/ Done

Spec ==
    /\ Init /\ [][Next]_vars
    /\ \A c \in Callers : WF_vars(Progress(c))
    /\ \A k \in TagKeys : WF_vars(TRead(k) \/ TWrite(k))
    /\ \A t \in Tokens : WF_vars(Expire(t))

-----------------------------------------------------------------------------
\* Properties. Each names the code it models.

TypeOK ==
    /\ inst.spec \subseteq Vols
    /\ inst.tags \subseteq InitTags \cup TagKeys
    /\ \A v \in Vols : inst.rec[v] \in Tokens \cup {None} /\ inst.dop[v] \in Tokens \cup {None}
    /\ \A c \in Callers : pc[c] \in Live \cup {"done", "gone"} /\ result[c] \in Results \cup {None}

\* No volume is detached twice for one op id. ec2.go detachOnce checks the
\* record before the spec, and writeDetach sends RequestId
\* requestUUID(key, "detach"), which compute replays within the window.
DetachOnce == \A t \in Tokens : applied[t] <= 1

\* A replay returns the first result: a success answers this request's own
\* operation, never another detach's. ec2.go detachReplay.opMatch,
\* detachFPToken; writeDetach deletes the old vws-dop- next to a new record.
ReplayReturnsFirst == \A c \in Callers : result[c] = "ok" => retop[c] = tokOf[c]

\* The label count never exceeds the budget, and no write the client sends
\* is refused by compute for it: an accepted detach always has room for its
\* op id. ec2.go instanceUpdateLabels (pendingDetachOps), detachRoomErr.
LabelBudget ==
    /\ Count(inst) <= Budget
    /\ \A c \in Callers : result[c] \notin {"capacity", "lost"}
    /\ \A k \in TagKeys : tpc[k] # "capacity"

\* Prune never removes a record a live op still needs: no write drops a
\* record while a caller holding its token is still running (its replay
\* reads that record). ec2.go pruneDetachRecords, called from
\* instanceUpdateLabels on every new label write.
PruneKeepsLive == ~liveDropped

\* A hold blocks prune: no write drops an expired record while a recovery is
\* pending. ec2.go detachRecoveryPending, pruneDetachRecords.
HoldBlocksPrune == ~heldPruned

\* No lost update under concurrent label writes: every applied tag write
\* is still on the instance, since tags are only added. Every instance
\* write in ec2.go carries the etag it read (writeDetach, persistDetachOp,
\* CreateTags).
NoLostUpdate == acked \subseteq inst.tags

\* FINDINGS: the current code breaks these two; scripts/tla-detach.sh
\* expects each to fail (see docs/formal/README.md).
\*
\* A recovery resend matches the original write: a retry of a detach whose
\* op id was not saved is never refused as a fingerprint mismatch.
\* ec2.go writeDetach(drop=false) rebuilds the update from the instance as
\* it is now (tags, spec.volumes, other records), not as it was written.
ResendMatchesOriginal == \A c \in Callers : result[c] # "mismatch"

\* A retry of an accepted detach is never answered "not in use": the record
\* it replays survives a later detach of the same volume. ec2.go keeps one
\* record per volume (vws-detach-<vol>), and writeDetach overwrites it.
ReplaySurvivesLaterDetach ==
    \A c \in Callers : tokOf[c] \in accepted => result[c] # "notinuse"

\* Liveness: no DetachVolume call is stuck; every pending recovery ends.
CallsFinish == <>(\A c \in Callers : pc[c] \notin Live)
HoldEnds == <>[](Pending(inst) = 0)

=============================================================================
