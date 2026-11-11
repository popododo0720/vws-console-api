----------------------------- MODULE instance -----------------------------
EXTENDS Naturals, FiniteSets

CONSTANTS VMs, Tokens, None, FixReplay, FixStart, FixDestroy, FixFence

\* AWS EC2 User Guide, ec2-instance-lifecycle.html (2026-11-11).
\* Parsed by TestInstanceTransitionsMatchModel.
AllowedTransitions == {
    <<"pending", "running">>,
    <<"pending", "shutting-down">>,
    <<"running", "running">>,
    <<"running", "stopping">>,
    <<"running", "shutting-down">>,
    <<"stopping", "stopped">>,
    <<"stopping", "shutting-down">>,
    <<"stopped", "pending">>,
    <<"stopped", "shutting-down">>,
    <<"shutting-down", "terminated">>
}

States == {"pending", "running", "stopping", "stopped",
           "shutting-down", "terminated"}
Kinds == {"clone", "config", "start", "stop", "reboot", "destroy"}
Statuses == {"idle", "running", "ok", "failed"}

VARIABLES state, exists, owner, upid, status, leader, quorum, request,
          scanned, legal, fenced
vars == <<state, exists, owner, upid, status, leader, quorum, request,
          scanned, legal, fenced>>

Init ==
    /\ state = [v \in VMs |-> None]
    /\ exists = {}
    /\ owner = [v \in VMs |-> None]
    /\ upid = [v \in VMs |-> None]
    /\ status = [v \in VMs |-> "idle"]
    /\ leader = TRUE
    /\ quorum = TRUE
    /\ request = None
    /\ scanned = FALSE
    /\ legal = TRUE
    /\ fenced = TRUE

\* Each (VM, kind) denotes a UPID; attempts with the same outcome are
\* equivalent here. PVE serializes tasks on a VM, including across terms.
Gate == ~FixFence \/ (leader /\ quorum)
Submit(v, kind) ==
    /\ Gate
    /\ upid' = [upid EXCEPT ![v] = <<v, kind>>]
    /\ status' = [status EXCEPT ![v] = "running"]
    /\ fenced' = (fenced /\ leader /\ quorum)

\* legal records every edge, rather than constraining Next with the oracle.
Change(v, s) ==
    /\ state' = [state EXCEPT ![v] = s]
    /\ legal' = (legal /\ (s = state[v] \/ <<state[v], s>> \in AllowedTransitions))

\* A retry rereads PVE markers, never a daemon-local idempotency cache.
Lookup(t) ==
    /\ request' = t
    /\ scanned' = TRUE
    /\ UNCHANGED <<state, exists, owner, upid, status, leader, quorum, legal, fenced>>

Clone(v) ==
    /\ scanned
    /\ owner[v] = None
    /\ ~FixReplay \/ ~(\E w \in exists : owner[w] = request)
    /\ Submit(v, "clone")
    /\ owner' = [owner EXCEPT ![v] = request]
    /\ exists' = exists \cup {v}
    /\ state' = [state EXCEPT ![v] = "pending"]
    /\ scanned' = FALSE
    /\ UNCHANGED <<leader, quorum, request, legal>>

Configure(v) ==
    /\ v \in exists
    /\ upid[v] = <<v, "clone">> /\ status[v] = "ok"
    /\ Submit(v, "config")
    /\ UNCHANGED <<state, exists, owner, leader, quorum, request, scanned, legal>>

Start(v) ==
    /\ v \in exists
    /\ \/ /\ state[v] = "pending"
          /\ upid[v] = <<v, "config">> /\ status[v] = "ok"
       \/ /\ state[v] = "stopped" /\ status[v] # "running"
    /\ Submit(v, "start")
    /\ IF state[v] = "stopped"
       THEN Change(v, IF FixStart THEN "pending" ELSE "running")
       ELSE UNCHANGED <<state, legal>>
    /\ UNCHANGED <<exists, owner, leader, quorum, request, scanned>>

Stop(v) ==
    /\ v \in exists
    /\ state[v] \in {"running", "stopping"}
    /\ status[v] # "running"
    /\ Submit(v, "stop")
    /\ Change(v, "stopping")
    /\ UNCHANGED <<exists, owner, leader, quorum, request, scanned>>

Reboot(v) ==
    /\ v \in exists /\ state[v] = "running" /\ status[v] # "running"
    /\ Submit(v, "reboot")
    /\ UNCHANGED <<state, exists, owner, leader, quorum, request, scanned, legal>>

\* A failed launch is undone by the same destroy path as Terminate.
\* A failed stop/destroy remains transitional until retried; task failure
\* alone does not prove that PVE rolled back a physical side effect.
Terminate(v) ==
    /\ v \in exists /\ status[v] # "running"
    /\ Submit(v, "destroy")
    /\ Change(v, "shutting-down")
    /\ UNCHANGED <<exists, owner, leader, quorum, request, scanned>>

\* Already submitted tasks finish even after quorum/leader loss or restart.
Finish(v, success) ==
    /\ status[v] = "running"
    /\ status' = [status EXCEPT ![v] = IF success THEN "ok" ELSE "failed"]
    /\ IF ~success
       THEN UNCHANGED <<state, exists, legal>>
       ELSE LET kind == upid[v][2]
                next == CASE kind = "start" -> "running"
                          [] kind = "stop" -> "stopped"
                          [] kind = "destroy" -> "terminated"
                          [] OTHER -> state[v]
            IN /\ Change(v, next)
               /\ exists' = IF kind = "destroy" /\ FixDestroy
                            THEN exists \ {v} ELSE exists
    /\ UNCHANGED <<owner, upid, leader, quorum, request, scanned, fenced>>

\* Lease expiry drops authority; acquisition represents the next term,
\* after the previous lease expires. Quorum loss fences immediately.
Authority ==
    /\ leader' \in BOOLEAN
    /\ quorum' \in BOOLEAN
    /\ (leader' => quorum')
    /\ UNCHANGED <<state, exists, owner, upid, status, request, scanned, legal, fenced>>

Restart ==
    /\ leader' = FALSE
    /\ scanned' = FALSE
    /\ request' = None
    /\ UNCHANGED <<state, exists, owner, upid, status, quorum, legal, fenced>>

Next ==
    \/ \E t \in Tokens : Lookup(t)
    \/ \E v \in VMs : Clone(v) \/ Configure(v) \/ Start(v) \/ Stop(v)
                      \/ Reboot(v) \/ Terminate(v) \/ Finish(v, TRUE) \/ Finish(v, FALSE)
    \/ Authority
    \/ Restart

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ state \in [VMs -> States \cup {None}]
    /\ exists \subseteq VMs
    /\ owner \in [VMs -> Tokens \cup {None}]
    /\ upid \in [VMs -> (VMs \X Kinds) \cup {None}]
    /\ status \in [VMs -> Statuses]
    /\ request \in Tokens \cup {None}
    /\ scanned \in BOOLEAN /\ (scanned => request \in Tokens)
    /\ leader \in BOOLEAN /\ quorum \in BOOLEAN
    /\ legal \in BOOLEAN /\ fenced \in BOOLEAN
OneVMPerClientToken ==
    \A t \in Tokens : Cardinality({v \in exists : owner[v] = t}) <= 1
AllowedEdges == legal
NoOrphanAfterTerminate ==
    \A v \in VMs : state[v] = "terminated" => v \notin exists
MutationsFenced == fenced
=============================================================================
