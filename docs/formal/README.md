# Formal models

## Instance lifecycle (`instance.tla`, #881)

`instance.tla` specifies the phase-2 Proxmox lifecycle before mutation
handlers are implemented. Last confirmed against backend commit `bd4b775`
(the read-only backend); the transition contract added here is
`internal/backend/proxmox/lifecycle.go`. This is a design check, not evidence
that the future handlers already implement its guards.

Run `scripts/tla-instance.sh` with Java 11+. The `instance` job in
`.github/workflows/tla.yml` checks the design, every seeded counterexample,
and Go/model table parity. The runner uses the same immutable jar pin as
`scripts/tla-detach.sh`; `scripts/tla-instance_test.sh` checks the pins agree.
The shell regression also exercises fake Java exits and conflicting output
without Java or network access. A clean model needs exit 0 and the success
verdict with no errors. Each seed needs exit 12 and its named invariant
violation; only TLC's standard counterexample trace heading may accompany
that error. Any other error or exit status fails the runner.

`AllowedTransitions` transcribes the arrows, including the running reboot
self-edge, in the [EC2 lifecycle diagram](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-lifecycle.html)
(read 2026-11-11). Launch creates a new identity in pending; unchanged
observations and failed tasks do not count as state transitions.
`InstanceTransitions()` returns an independent Go table on each call.
`TestInstanceTransitionsMatchModel` parses the actual TLA+ table and compares
every edge; `TestInstanceTransitionTableBoundary` rejects malformed,
unknown and duplicate model rows and checks terminal-state boundaries.

| Model | Planned mechanism (design.md 3.3, 4.9, 5.4) |
| --- | --- |
| `Clone`, `owner`, `exists` | clone POST creates a VM with its ClientToken key in the PVE description; a retry scans markers before allocating |
| `Configure`, `Start` | clone UPID completes, config UPID completes, start UPID completes; pending persists until start succeeds |
| `Stop`, `Reboot`, `Terminate` | per-VM task submission; stop enters stopping, reboot stays running, destroy enters shutting-down |
| `Finish` | PVE task finishes OK or fails independently of the daemon; only successful destroy removes the VM and reports terminated |
| `Authority`, `Gate` | lease expiry/loss, next-term acquisition and quorum loss/recovery; every submission checks current authority |
| `Restart`, `Lookup` | local lookup and leadership are lost; PVE markers and UPIDs survive, and the same token can be retried |

| Invariant | Seed that breaks it |
| --- | --- |
| `OneVMPerClientToken`: at most one existing VM per token | `FixReplay=FALSE`: allocate again instead of reusing its marker |
| `AllowedEdges`: every changed state follows the table | `FixStart=FALSE`: stopped goes directly to running |
| `NoOrphanAfterTerminate`: terminated implies no physical VM | `FixDestroy=FALSE`: publish terminated without deleting the VM |
| `MutationsFenced`: every submission had leader and quorum | `FixFence=FALSE`: submit after authority loss |

Bounds: two VM identities and two tokens, all interleavings, unlimited
retries, task failures, authority changes and restarts within that finite
state space. A token represents one RunInstances index; multi-instance
reservations need one such key/index pair per VM. UPIDs are abstract
`(VM, task kind)` pairs; repeat attempts are equivalent for these safety
properties. Failed launch tasks retain their marker and use the destroy
path for undo. Failed stop/destroy tasks stay transitional and can retry.
No liveness is claimed under perpetual task failure or absent quorum.
Local TLC result: 11,433 distinct states, depth 21, no violations; all four
seeded bugs produce their named counterexample.

Assumptions required of the future handlers: one lease holder at a time,
per-VM serialization across terms, and serialized marker lookup plus clone
submission, with the marker visible before another leader may allocate.
The model abstracts lease time and fencing margin into current authority;
it does not prove the pmxcfs lock protocol or network-delayed POST fencing.
It does not cover pools, fingerprint mismatch, disk preservation, snippets,
or guest-initiated changes. Go boundary tests cover invalid table input;
there is no new API input parser here.

Uniqueness counts existing VMs, not historical allocations. The documented
design gap remains: after Terminate removes PVE markers and a restart
loses the leader cache, the same token may launch a new VM. There is no
persistent tombstone in this model. Terminated is a proof state for
successful destroy; the planned Describe API returns NotFound afterward.

The Proxmox drive-serial/holder replacement for `detach.tla` (AC 3) is left
for the next part of #881 to keep each PR within the 800-line budget. The
existing gRPC detach model and its checks remain below.

## DetachVolume recovery path

`detach.tla` is a TLA+ model of how the gRPC backend detaches an EBS volume
and recovers a detach that was interrupted (#343). It checks every
interleaving of two concurrent `DetachVolume` callers, a concurrent
`CreateTags`, an `AttachVolume` that puts a detached volume back, console-api
restarts at any step, and the client-token window passing.

Run it with `scripts/tla-detach.sh` (needs Java 11+; about 5 minutes on 8
cores). CI runs it in `.github/workflows/tla.yml`.

The IAM authorize, then read or write model is `iamauth.tla`, described in
`iamauth.md` (#373).

Last confirmed against the code at commit `6fd3fcb` with the #334 change. When a file in
"Coverage" changes after that commit, read the change against the model
before trusting a pass, and move this commit forward only once the model
describes the new code.

## What is modeled

| Model | Code |
| --- | --- |
| `inst.spec` | the instance's `spec.volumes` (the attachment) |
| `inst.rec[v]` | label `vws-detach-<vol>`: `detachRecordValue`, `parseDetachRecord` |
| `inst.dop[v]` | label `vws-dop-<vol>`: `persistDetachOp`, `detachFPToken` |
| `inst.tags`, `Count`, `Budget` | user tags and records against `labelMax` (`names.go`) |
| `etag`, `Compute` | vws-compute `UpdateInstance`: request id replay, etag, label limit |
| `reqStore` | vws-compute's request id store (`requestUUID(key, "detach")`) |
| `expired`, `Expire` | `backend.ClientTokenExpired` (`internal/backend/backend.go`) |
| `Read` | `detachOnce`, `detachBind`, `writeDetach` before the call, `detachRecordsInWindow`, `instanceUpdateLabels` |
| `Write` | `writeDetach`'s `UpdateInstance`; `etagMismatchError` reread in `DetachVolume` |
| `PRead`, `PWrite` | `persistDetachOp` |
| `Prune`, `PruneHeld`, `Hold`, `Pending` | `pruneDetachRecords`, `pruneHeldDetachRecords`, `detachRecoveryPending`, `pendingDetachOps` |
| `Pruned` | `instanceUpdateLabels`: the hold stays while the write has room, and ends when it has none (#334) |
| `TRead`, `TWrite` | `CreateTags` through `instanceUpdateLabels` |
| `Reattach` | `AttachVolume` through `instanceUpdateLabels` |
| `Restart`, `Abandon` | a console-api restart or lost response (the client retries with the same token), or a client that gives up |

All in `internal/backend/grpcclient/ec2.go` unless named otherwise. Every
RPC is one step, as in the code; compute applies one `UpdateInstance`
atomically. `AttachVolume`'s read-modify-write is one step.

## Properties

| Property | Plain meaning | Code it guards | Seeded bug that breaks it |
| --- | --- | --- | --- |
| `DetachOnce` | No volume is detached twice for one client token. | `detachOnce` checks the record first; `writeDetach` sends `RequestId` `requestUUID(key, "detach")` | `WithinWindow=FALSE`: a retry after the window, after a reattach |
| `ReplayReturnsFirst` | A successful retry answers its own operation, never another detach's. | `detachReplay.opMatch`, `detachFPToken`; `writeDetach` deletes the old `vws-dop-` | `FixOpBinding=FALSE` with `FixArchive=FALSE` (before #213, #302; the archive moves the old op id with its record, so it hides this seed alone) |
| `LabelBudget` | Labels never pass the limit, and compute never refuses a write for it: an accepted detach always has room for its op id. | `instanceUpdateLabels` (`pendingDetachOps`), `detachRoomErr` | `FixPendingReserve=FALSE`: the #327 race |
| `PruneKeepsLive` | No write removes a record a running caller's retry still reads. | `pruneDetachRecords` | `FixPruneExpiredOnly=FALSE` |
| `HoldBlocksPrune` | No write prunes an expired record while a recovery is pending, unless the write has no room for it. | `detachRecoveryPending`, `pruneDetachRecords` | `FixHold=FALSE` (before #319) |
| `HoldNeverRefuses` | A hold never refuses a tag write that fits once the hold ends: records are not EC2 tags. | `instanceUpdateLabels` (#334) | `FixHoldGivesWay=FALSE`: the #327 hold keeps an expired record and refuses the tag |
| `NoLostUpdate` | A tag write that compute applied is never overwritten by a concurrent write. | the etag on every `UpdateInstance` in `writeDetach`, `persistDetachOp`, `CreateTags` | `FixEtagCAS=FALSE` |
| `CallsFinish` (liveness) | Every `DetachVolume` call returns. | the reread loop in `DetachVolume` | `FixEtagReread=FALSE`: resend the stale write on an etag mismatch |
| `HoldEnds` (liveness) | Every pending recovery ends. | `pendingDetachOps` skips expired records (#322) | `FixPendingExpires=FALSE` |
| `ReplaySurvivesLaterDetach` | A retry of an accepted detach is never answered "not in use" after a later detach of the volume. | `archiveDetachRecord`, `detachReplayFor` (#353); archive slots `<<v, t>>` | `FixArchive=FALSE` |
| `RetryKeepsItsParams` | A same-token retry of an accepted detach is never answered `IdempotentParameterMismatch`: the op id next to its record is its own. | `persistDetachOp` saves the id in the slot `detachReplayFor` finds (#359) | `FixPersistOwnSlot=FALSE`: the id goes under the volume's own key, over a later detach's record |

`scripts/tla-detach.sh` checks the real design (every `Fix*` TRUE) with all
properties, then each seeded bug against the property it guards, and fails
unless each seeded bug produces a counterexample.

The #327 race, as TLC finds it with `FixPendingReserve=FALSE` (budget 3, one
user tag): detach of v1 writes its record (2 labels, room for its op id); a
`CreateTags` adds a tag (3 labels, no room kept for the op id); the detach's
`persistDetachOp` write needs a 4th label, compute refuses it, and the
accepted detach answers an error with no op id saved.

The `persistDetachOp` slot bug, as TLC finds it with
`FixPersistOwnSlot=FALSE` (10 states): t1 detaches v1; v1 is reattached;
t2 detaches v1, which moves t1's record to its archive slot; t1's
`persistDetachOp` saves its op id under `vws-dop-v1`, next to t2's record;
t2's retry after a restart reads an op id of other parameters and answers
`IdempotentParameterMismatch`. Every other property passes with this bug.

## Bounds and assumptions

- 2 callers, 2 tokens (callers may share one: a replay), 2 volumes, every
  assignment of tokens to callers and volumes to tokens.
- Label budget 3 or 4 (both are checked: 3 reaches the #327 race, 4 reaches
  the hold), starting with 0 or 1 user tags, and one concurrent tag write.
  `MaxReplays` 2 (the code's `backend.MaxDetachReplays` is 4).
- Up to 2 restarts and 1 reattach per run.
- `WithinWindow`: no caller retries a token after its record expired (#305
  covers that case).
- Real design result: 5,045,040 distinct states, 0 violations, depth 26.

## Not modeled

- Records stored unstamped by older code (before #303, or before #329 with
  a device name over 23 bytes) and the `stampedRecordExpired` rule. Every
  record the code writes now is stamped (#329).
- Records written before #362, with no `vws-dop-` label. `dop[v] = None`
  next to a record stands for the fingerprint binding the first write leaves.
- More than one instance: `findDetachReplay` paging, a volume moved to
  another instance, `volumeBoundElsewhere`.
- The 5-attempt bound on the etag loops, the post-replay etag check
  (`!drop && updated.GetDone()`), boot volumes, minted tokens.
- Storage-side state (`DescribeVolumes` attaching/detaching display).

## Findings in the current code

None. `scripts/tla-detach.sh` keeps a finding list for properties that fail
on the real design; a fix shows up as a failing CI step, and the property
then moves into `detach.cfg`. Both earlier findings now hold:

1. `ReplaySurvivesLaterDetach` (#353): a new record moves another request's
   record to an archive slot.
2. `ResendMatchesOriginal` (#352): a retry of a detach whose op id was not
   saved rebuilds the `UpdateInstance` from the instance as it is now; if
   anything changed in between (a tag, another detach, another record's op
   id save), compute answers a fingerprint mismatch. With
   `FixResendRecover`, on `IDEMPOTENCY_CONFLICT` `writeDetach` rereads the
   instance and, next to this request's record (also in its archive slot),
   saves an op of the instance as it is. The seed `seed-resend`
   (`FixResendRecover=FALSE`) brings the violation back. The code also binds
   the record to the request's fingerprint from the first write (a
   placeholder `vws-dop-` value), so a same-token retry with other
   parameters is refused before it can recover; the model has one parameter
   set per token and does not cover that half (`TestRecoveryRefusesOtherParameters`).

## Coverage

`internal/backend/grpcclient/ec2.go` (`DetachVolume`, `detachOnce`,
`detachBind`, `writeDetach`, `persistDetachOp`, `instanceUpdateLabels`,
`pruneDetachRecords`, `detachRecoveryPending`, `pendingDetachOps`,
`detachRecordsInWindow`, `detachReplayFrom`, `opMatch`, `CreateTags`,
`AttachVolume`), `internal/backend/grpcclient/names.go` (`labelMax`),
`internal/backend/backend.go` (`ClientTokenWindow`, `ClientTokenExpired`,
`MaxDetachReplays`).
