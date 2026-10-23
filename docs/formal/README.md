# Formal model: DetachVolume recovery path

`detach.tla` is a TLA+ model of how the gRPC backend detaches an EBS volume
and recovers a detach that was interrupted (#343). It checks every
interleaving of two concurrent `DetachVolume` callers, a concurrent
`CreateTags`, an `AttachVolume` that puts a detached volume back, console-api
restarts at any step, and the client-token window passing.

Run it with `scripts/tla-detach.sh` (needs Java 11+; about 5 minutes on 8
cores). CI runs it in `.github/workflows/tla.yml`.

Last confirmed against the code at commit `8485d5a`. When a file in
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
| `ReplayReturnsFirst` | A successful retry answers its own operation, never another detach's. | `detachReplay.opMatch`, `detachFPToken`; `writeDetach` deletes the old `vws-dop-` | `FixOpBinding=FALSE` (before #213, #302) |
| `LabelBudget` | Labels never pass the limit, and compute never refuses a write for it: an accepted detach always has room for its op id. | `instanceUpdateLabels` (`pendingDetachOps`), `detachRoomErr` | `FixPendingReserve=FALSE`: the #327 race |
| `PruneKeepsLive` | No write removes a record a running caller's retry still reads. | `pruneDetachRecords` | `FixPruneExpiredOnly=FALSE` |
| `HoldBlocksPrune` | No write prunes an expired record while a recovery is pending. | `detachRecoveryPending`, `pruneDetachRecords` | `FixHold=FALSE` (before #319) |
| `NoLostUpdate` | A tag write that compute applied is never overwritten by a concurrent write. | the etag on every `UpdateInstance` in `writeDetach`, `persistDetachOp`, `CreateTags` | `FixEtagCAS=FALSE` |
| `CallsFinish` (liveness) | Every `DetachVolume` call returns. | the reread loop in `DetachVolume` | `FixEtagReread=FALSE`: resend the stale write on an etag mismatch |
| `HoldEnds` (liveness) | Every pending recovery ends. | `pendingDetachOps` skips expired records (#322) | `FixPendingExpires=FALSE` |

`scripts/tla-detach.sh` checks the real design (every `Fix*` TRUE) with all
properties, then each seeded bug against the property it guards, and fails
unless each seeded bug produces a counterexample.

The #327 race, as TLC finds it with `FixPendingReserve=FALSE` (budget 3, one
user tag): detach of v1 writes its record (2 labels, room for its op id); a
`CreateTags` adds a tag (3 labels, no room kept for the op id); the detach's
`persistDetachOp` write needs a 4th label, compute refuses it, and the
accepted detach answers an error with no op id saved.

## Bounds and assumptions

- 2 callers, 2 tokens (callers may share one: a replay), 2 volumes, every
  assignment of tokens to callers and volumes to tokens.
- Label budget 3 or 4 (both are checked: 3 reaches the #327 race, 4 reaches
  the hold), starting with 0 or 1 user tags, and one concurrent tag write.
  `MaxReplays` 2 (the code's `backend.MaxDetachReplays` is 4).
- Up to 2 restarts and 1 reattach per run.
- `WithinWindow`: no caller retries a token after its record expired (#305
  covers that case).
- Real design result: 3,381,576 distinct states, 0 violations, depth 18.

## Not modeled

- Records written before #303 (no stamp) and the `writtenBefore303` /
  `stampedRecordExpired` rule.
- More than one instance: `findDetachReplay` paging, a volume moved to
  another instance, `volumeBoundElsewhere`.
- The 5-attempt bound on the etag loops, the post-replay etag check
  (`!drop && updated.GetDone()`), boot volumes, minted tokens.
- Storage-side state (`DescribeVolumes` attaching/detaching display).

## Findings in the current code

Two properties fail on the real design. `scripts/tla-detach.sh` expects them
to fail, so a fix shows up as a failing CI step: then move the property into
`detach.cfg` and drop it from the script's finding list.

1. `ResendMatchesOriginal`: a retry of a detach whose op id was not saved
   rebuilds the `UpdateInstance` from the instance as it is now. If
   anything changed in between, compute answers a fingerprint mismatch, and
   the accepted detach answers `IdempotencyMismatch` to its own retry. A
   changed tag is confirmed against the repo's compute fake; by the code, a
   detach of another volume or another record's op id save does the same,
   since the resend carries the current `spec.volumes` and records. TLC:
   detach of v1 is accepted, its op id not yet saved; `CreateTags` adds a
   tag; a retry with the same token resends with the new tag; compute
   refuses it.
2. `ReplaySurvivesLaterDetach`: there is one record per volume. After a
   reattach, a detach with another token overwrites the first detach's
   record, so the first detach's retry answers `IncorrectState` (volume
   available) instead of its result. TLC: detach A of v1 is accepted, the
   client restarts; v1 is attached again; detach B of v1 is accepted; A's
   retry finds no record for its token.

## Coverage

`internal/backend/grpcclient/ec2.go` (`DetachVolume`, `detachOnce`,
`detachBind`, `writeDetach`, `persistDetachOp`, `instanceUpdateLabels`,
`pruneDetachRecords`, `detachRecoveryPending`, `pendingDetachOps`,
`detachRecordsInWindow`, `detachReplayFrom`, `opMatch`, `CreateTags`,
`AttachVolume`), `internal/backend/grpcclient/names.go` (`labelMax`),
`internal/backend/backend.go` (`ClientTokenWindow`, `ClientTokenExpired`,
`MaxDetachReplays`).
