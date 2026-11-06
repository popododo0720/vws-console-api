------------------------------ MODULE iamauth ------------------------------
(***************************************************************************)
(* IAM authorize, then read or write a named entity (#373, #331 family).   *)
(*                                                                         *)
(* The Query surface resolves a named user, group or role to its ARN       *)
(* (iam.Resolver), authorizes the action on that ARN (iam.Authorize) and   *)
(* passes the AuthorizedPrincipal to one iam.Admin call. Over gRPC         *)
(* (internal/backend/grpcclient/iamclient) that call reads the entity,     *)
(* binds its ARN to the principal (AuthorizedPrincipal.Bind), then reads   *)
(* or writes the entity's data in further RPCs. Between any two RPCs       *)
(* another admin may move the entity: UpdateUser or UpdateGroup NewPath,   *)
(* or a role deleted and created again on another path. A move changes    *)
(* the ARN and the etag; a move away and back restores the ARN only.       *)
(*                                                                         *)
(* What one step is: every RPC is its own step, as in the code. The        *)
(* Resolver lookup and the Authorize decision are one step: the decision   *)
(* is about the ARN the lookup answered, whatever happens after it.        *)
(*                                                                         *)
(* Abstractions (see docs/formal/iamauth.md):                              *)
(*  - One entity, at an allowed ARN (path) or a denied one. Policy allows  *)
(*    every ARN but Denied, as a Deny on the real path does; Guess is the  *)
(*    path-less ARN a failed lookup would guess, which that Deny misses.   *)
(*  - An action is its Shape, the way its Admin call reaches the data.     *)
(*  - tainted[r] is a ghost: request r read or wrote the entity's data     *)
(*    while its ARN was not the authorized one.                            *)
(*  - The fake backend (internal/iam/store.go) binds and acts under one    *)
(*    lock, so every call there is one step and cannot fail these.         *)
(*                                                                         *)
(* Fix* constants switch one guard of the real code off, to show that the  *)
(* property it guards can fail. The real design has every Fix* TRUE.       *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Reqs,        \* concurrent Query requests on the entity
    Allowed,     \* ARNs (paths) the caller is allowed on
    Denied,      \* the ARN a Deny names; Allowed and Denied are disjoint
    Guess,       \* the path-less ARN of the requested name
    Zero,        \* the zero AuthorizedPrincipal
    MaxMoves,    \* moves of the entity by another admin over the run
    MaxRestarts, \* console-api restarts over the run
    FixFailClosed, \* a failed lookup authorizes nothing (#358)
    FixBind,       \* every entity read compares its ARN with the principal (#331, #342)
    FixPageEtag,   \* a read of several calls compares the etag of its first and last user reads (#407)
    FixWriteEtag,  \* a write carries the etag of the read that bound it
    FixExpectARN,  \* an access key write carries expected_user_arn (#340)
    FixUndoEtag    \* EnableMFADevice's reread compares the etag, not the ARN only

ARNs == Allowed \cup Denied

(* The Admin calls modeled, each by the code path it takes. *)
Actions == {"GetUser", "ListAccessKeys", "UpdateUser", "UpdateAccessKey",
            "EnableMFADevice", "CreateAccessKey", "UpdateRole"}

Shape == [a \in Actions |->
    CASE a = "GetUser"         -> "read"   \* users_groups.go GetUser: bind and data in one GetUser
      [] a = "ListAccessKeys"  -> "pages"  \* access_keys.go: boundUser, pages, unchangedUser
      [] a = "UpdateUser"      -> "cas"    \* users_groups.go UpdateUser: write under the bound read's etag
      [] a = "UpdateAccessKey" -> "expect" \* access_keys.go: keyUser, write with ExpectedUserArn
      [] a = "EnableMFADevice" -> "undo"   \* admin.go: boundUser, enable, unchangedUser, undo
      [] a = "CreateAccessKey" -> "none"   \* access_keys.go: keyUser, then a create with no precondition
      [] a = "UpdateRole"      -> "none"]  \* admin.go: roleAt, then UpdateRole with no etag

VARIABLES
    arn,      \* the entity's current ARN
    etag,     \* the entity's etag; every move or write of it changes it
    moves,    \* moves so far
    restarts, \* restarts so far
    act,      \* act[r]: the action request r runs
    pc,       \* pc[r]: the next step of request r
    want,     \* want[r]: the principal Authorize returned, or Zero
    authOn,   \* authOn[r]: the entity's ARN when r was authorized (ghost)
    etag0,    \* etag0[r]: the etag of r's bind read
    page,     \* page[r]: data pages r has read
    applied,  \* applied[r]: r's write is in place
    tainted,  \* tainted[r]: r touched data while arn # want[r] (ghost)
    result    \* result[r]: what r answers

vars == <<arn, etag, moves, restarts, act, pc, want, authOn, etag0, page,
          applied, tainted, result>>

Steps == {"auth", "bind", "page", "verify", "write", "undo", "done"}
Results == {"none", "ok", "changed", "denied", "unavailable", "lost"}

TypeOK ==
    /\ arn \in ARNs
    /\ etag \in 0..(MaxMoves + Cardinality(Reqs))
    /\ moves \in 0..MaxMoves
    /\ restarts \in 0..MaxRestarts
    /\ act \in [Reqs -> Actions]
    /\ pc \in [Reqs -> Steps]
    /\ want \in [Reqs -> ARNs \cup {Guess, Zero}]
    /\ authOn \in [Reqs -> ARNs \cup {Zero}]
    /\ etag0 \in [Reqs -> Nat]
    /\ page \in [Reqs -> 0..2]
    /\ applied \in [Reqs -> BOOLEAN]
    /\ tainted \in [Reqs -> BOOLEAN]
    /\ result \in [Reqs -> Results]

Init ==
    /\ arn \in Allowed
    /\ etag = 0
    /\ moves = 0
    /\ restarts = 0
    /\ act \in [Reqs -> Actions]
    /\ pc = [r \in Reqs |-> "auth"]
    /\ want = [r \in Reqs |-> Zero]
    /\ authOn = [r \in Reqs |-> Zero]
    /\ etag0 = [r \in Reqs |-> 0]
    /\ page = [r \in Reqs |-> 0]
    /\ applied = [r \in Reqs |-> FALSE]
    /\ tainted = [r \in Reqs |-> FALSE]
    /\ result = [r \in Reqs |-> "none"]

Finish(r, res) ==
    /\ pc' = [pc EXCEPT ![r] = "done"]
    /\ result' = [result EXCEPT ![r] = res]

Touch(r) == tainted' = [tainted EXCEPT ![r] = tainted[r] \/ arn # want[r]]

(* AuthorizedPrincipal.Bind on a read of the entity. *)
Bound(r) == ~FixBind \/ arn = want[r]

(* The Resolver lookup and Authorize (iamquery.go, actions.go). A lookup  *)
(* that fails with anything but NoSuchEntity answers an error; the bug    *)
(* guesses the path-less ARN, which a Deny on the real path misses.       *)
Auth(r) ==
    /\ pc[r] = "auth"
    /\ \/ /\ arn \in Denied
          /\ Finish(r, "denied")
          /\ UNCHANGED <<want, authOn>>
       \/ /\ arn \notin Denied
          /\ want' = [want EXCEPT ![r] = arn]
          /\ authOn' = [authOn EXCEPT ![r] = arn]
          /\ pc' = [pc EXCEPT ![r] = "bind"]
          /\ UNCHANGED result
       \/ /\ FixFailClosed
          /\ Finish(r, "unavailable")
          /\ UNCHANGED <<want, authOn>>
       \/ /\ ~FixFailClosed
          /\ want' = [want EXCEPT ![r] = Guess]
          /\ authOn' = [authOn EXCEPT ![r] = arn]
          /\ pc' = [pc EXCEPT ![r] = "bind"]
          /\ UNCHANGED result
    /\ UNCHANGED <<arn, etag, moves, restarts, act, etag0, page, applied, tainted>>

(* The first read of the Admin call: GetUser, rawUser, boundUser, keyUser, *)
(* roleAt, policyHolder. A "read" action's data comes in this same read.  *)
Bind(r) ==
    /\ pc[r] = "bind"
    /\ etag0' = [etag0 EXCEPT ![r] = etag]
    /\ IF ~Bound(r)
       THEN /\ Finish(r, "changed")
            /\ UNCHANGED tainted
       ELSE IF Shape[act[r]] = "read"
       THEN /\ Touch(r)
            /\ Finish(r, "ok")
       ELSE /\ pc' = [pc EXCEPT ![r] = IF Shape[act[r]] = "pages" THEN "page" ELSE "write"]
            /\ UNCHANGED <<result, tainted>>
    /\ UNCHANGED <<arn, etag, moves, restarts, act, want, authOn, page, applied>>

(* One data page of ListAccessKeys or ListMFADevices. Pages are not user *)
(* reads: they carry no ARN to bind.                                     *)
Page(r) ==
    /\ pc[r] = "page"
    /\ Touch(r)
    /\ page' = [page EXCEPT ![r] = page[r] + 1]
    /\ pc' = [pc EXCEPT ![r] = IF page[r] + 1 = 2 THEN "verify" ELSE "page"]
    /\ UNCHANGED <<arn, etag, moves, restarts, act, want, authOn, etag0, applied, result>>

(* unchangedUser: the user read again after the pages or the enable. *)
Unchanged(r, fixEtag) == Bound(r) /\ (fixEtag => etag = etag0[r])

Verify(r) ==
    /\ pc[r] = "verify"
    /\ IF Shape[act[r]] = "pages"
       THEN /\ Finish(r, IF Unchanged(r, FixPageEtag) THEN "ok" ELSE "changed")
       ELSE IF Unchanged(r, FixUndoEtag)
       THEN Finish(r, "ok")
       ELSE /\ pc' = [pc EXCEPT ![r] = "undo"]
            /\ UNCHANGED result
    /\ UNCHANGED <<arn, etag, moves, restarts, act, want, authOn, etag0, page, applied, tainted>>

(* The write RPC. vws-iam applies it atomically, checking the etag or     *)
(* expected_user_arn it carries; an UpdateUser write changes the etag.    *)
Write(r) ==
    /\ pc[r] = "write"
    /\ LET s == Shape[act[r]]
           ok == CASE s = "cas"    -> ~FixWriteEtag \/ etag = etag0[r]
                   [] s = "expect" -> ~FixExpectARN \/ arn = want[r]
                   [] OTHER        -> TRUE
       IN IF ~ok
          THEN /\ Finish(r, "changed")
               /\ UNCHANGED <<etag, applied, tainted>>
          ELSE /\ Touch(r)
               /\ applied' = [applied EXCEPT ![r] = TRUE]
               /\ etag' = IF s = "cas" THEN etag + 1 ELSE etag
               /\ IF s = "undo"
                  THEN /\ pc' = [pc EXCEPT ![r] = "verify"]
                       /\ UNCHANGED result
                  ELSE Finish(r, "ok")
    /\ UNCHANGED <<arn, moves, restarts, act, want, authOn, etag0, page>>

(* undoEnableMFADevice: DeactivateMfaDevice of the device just enabled. *)
Undo(r) ==
    /\ pc[r] = "undo"
    /\ applied' = [applied EXCEPT ![r] = FALSE]
    /\ Finish(r, "changed")
    /\ UNCHANGED <<arn, etag, moves, restarts, act, want, authOn, etag0, page, tainted>>

(* Another admin moves the entity: a new ARN and a new etag. *)
Move ==
    /\ moves < MaxMoves
    /\ \E a \in ARNs \ {arn}:
        /\ arn' = a
        /\ etag' = etag + 1
    /\ moves' = moves + 1
    /\ UNCHANGED <<restarts, act, pc, want, authOn, etag0, page, applied, tainted, result>>

(* console-api restarts: every running request is lost where it stands. *)
Restart ==
    /\ restarts < MaxRestarts
    /\ \E r \in Reqs: pc[r] # "done"
    /\ restarts' = restarts + 1
    /\ pc' = [r \in Reqs |-> "done"]
    /\ result' = [r \in Reqs |-> IF pc[r] = "done" THEN result[r] ELSE "lost"]
    /\ UNCHANGED <<arn, etag, moves, act, want, authOn, etag0, page, applied, tainted>>

(* Every request answered: the run ends. *)
Done == (\A r \in Reqs: pc[r] = "done") /\ UNCHANGED vars

Next ==
    \/ \E r \in Reqs: Auth(r) \/ Bind(r) \/ Page(r) \/ Verify(r) \/ Write(r) \/ Undo(r)
    \/ Move
    \/ Restart
    \/ Done

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* Properties. Each names the guard that keeps it; see iamauth.md. *)

ShapeIs(r, s) == Shape[act[r]] = s

(* A failed lookup authorizes nothing: every principal is the entity's   *)
(* real ARN at the time of the decision.                                  *)
AuthorizedOnRealARN == \A r \in Reqs: want[r] # Zero => want[r] = authOn[r]

(* A one-call read returns data only of the entity at the authorized ARN. *)
ReadsBound == \A r \in Reqs: ShapeIs(r, "read") /\ result[r] = "ok" => ~tainted[r]

(* A read of several calls returns no page read while the entity was     *)
(* elsewhere, a move away and back included.                              *)
PagesBound == \A r \in Reqs: ShapeIs(r, "pages") /\ result[r] = "ok" => ~tainted[r]

(* A guarded write never applies to the entity at another ARN. *)
WritesBound == \A r \in Reqs: (ShapeIs(r, "cas") \/ ShapeIs(r, "expect")) => ~tainted[r]

(* An EnableMFADevice that answered leaves no enable made at another ARN. *)
UndoCatchesMoves ==
    \A r \in Reqs: ShapeIs(r, "undo") /\ result[r] \in {"ok", "changed"}
                   => ~(applied[r] /\ tainted[r])

(* Findings in the current code (iamauth.md): *)

(* An enable made at another ARN does not stay after a restart. *)
EnableNeverStaysUnverified ==
    \A r \in Reqs: ShapeIs(r, "undo") /\ pc[r] = "done" => ~(applied[r] /\ tainted[r])

CreateAccessKeyBound == \A r \in Reqs: act[r] = "CreateAccessKey" => ~tainted[r]
UpdateRoleBound == \A r \in Reqs: act[r] = "UpdateRole" => ~tainted[r]
=============================================================================
