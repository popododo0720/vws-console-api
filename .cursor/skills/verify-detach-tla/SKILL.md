---
name: verify-detach-tla
description: >-
  Use when a change touches the gRPC DetachVolume recovery path in
  internal/backend/grpcclient/ec2.go (detach records, vws-dop- op ids, prune,
  hold, label budget, persistDetachOp, CreateTags or AttachVolume label
  writes), internal/backend/backend.go client-token window, or
  docs/formal/detach.tla. Model-checks the change with TLA+.
---
# Verify the DetachVolume recovery path

`docs/formal/detach.tla` models every interleaving of concurrent detaches,
same-token retries, a concurrent tag write, a reattach, console-api restarts
and the client-token window. `docs/formal/README.md` maps each model action
and property to the function it stands for, and lists the bounds and what is
not modeled.

## Does the change touch it?

Yes if it changes a function in the README's "Coverage" list, or the order
of reads and writes among them, or what a label write keeps, prunes or
counts. Compare against the sync commit in the README (`git diff <sync>..
-- <coverage files>`).

## Run

```bash
scripts/tla-detach.sh          # about 5 minutes on 8 cores
scripts/tla-detach.sh model    # only the real design
```

Needs Java 11+; the script downloads tla2tools 1.8.0 once and checks its
sha256. It passes when the real design has 0 violations, every seeded bug
(`Fix*=FALSE`) breaks the property it guards, and each known finding still
fails. Logs, with full TLC traces, are in the directory it prints.

## Reading a failure

- `model (real design): <Property>`: the change, as modeled, breaks the
  property. Read the trace in `model.log` as steps: `Read(c)` is
  `detachOnce` reading the instance, `Write(c)` its `UpdateInstance`,
  `PRead`/`PWrite` `persistDetachOp`, `TRead`/`TWrite` `CreateTags`,
  `Reattach` `AttachVolume`, `Restart` a console-api restart and same-token
  retry, `Expire` the 24-hour window passing. Reproduce it with a test in
  `internal/backend/grpcclient/detach_*_test.go` before calling it a bug.
- A seeded bug that passes: the model no longer exercises that fix. Fix the
  model, not the seed.
- A finding that passes: the code was fixed. Move the property into
  `docs/formal/detach.cfg` and drop it from the script's finding list.
- `broken`: TLC did not finish (a parse error or a deadlock); see the log.

## Changing the model with the code

When the change is intended, update the action in `detach.tla` that stands
for the changed function, keep each step one RPC, and keep its README row
true. A new fix gets a `Fix*` constant and a seeded line in
`scripts/tla-detach.sh`. Never weaken a property or the model to make a
finding pass. Move the README's sync commit forward only after you have read
the covered code at the new commit against the model.
