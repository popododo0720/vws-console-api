# Formal model: DetachVolume recovery path

`detach.tla` is a TLA+ model of how the gRPC backend detaches an EBS volume
and recovers a detach that was interrupted (#343). It checks every
interleaving of two concurrent `DetachVolume` callers, a concurrent
`CreateTags`, an `AttachVolume` that puts a detached volume back, console-api
restarts at any step, and the client-token window passing.

Run it with `scripts/tla-detach.sh` (needs Java 11+; about 5 minutes on 8
cores). CI runs it in `.github/workflows/tla.yml`.

Last confirmed against the code at commit `2fbef54`. When a file in
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
| `Prune`, `Hold`, `Pending` | `pruneDetachRecords`, `detachRecoveryPending`, `pendingDetachOps` |
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
| `HoldBlocksPrune` | No write prunes an expired record while a recovery is pending. | `detachRecoveryPending`, `pruneDetachRecords` | `FixHold=FALSE` (before #319) |
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
- Real design result: 4,934,768 distinct states, 0 violations, depth 26.

## Not modeled

- Records written before #303 (no stamp) and the `writtenBefore303` /
  `stampedRecordExpired` rule.
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
