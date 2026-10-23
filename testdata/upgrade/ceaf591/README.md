# Upgrade fixtures: ceaf591

`ceaf591` is the tip of `main` when #341 started. It is the build the previous
release's `publish.yml` published as `sha-ceaf591`; the repository has no tag or
GitHub release for it. These files are the records that build wrote, captured
before this change.

## Files

- `idempotency.json`: the mutation the kernel built for a `DetachVolume` call
  with client token `detach-upgrade-1`, including the normalized request.
- `detach-mid-flight.json`: an instance label map after a detach was accepted
  and before its operation id label was saved. The record has no `vws-dop-`
  label.
- `op-labels-budget.json`: fifty user tags, the internal labels, and four
  client-token detach records with their operation ids. That is 63 of compute's
  64 labels. `replay` names the record bound to `idempotency.json`.
- `held-record.json`: one expired record with its operation id and one record
  within the window whose operation id was never saved. The label write that
  produced the file ran while that recovery was pending, so the expired record
  is still there. `pendingOp` is the label the retry would save.

## Generator

`generate_test.go.txt` is the source. It is a test because it drives the
unexported record helpers and the kernel. It is not part of the build.

From a checkout of this repository with `ceaf591` in its history:

```sh
mkdir -p /tmp/vws-fixtures-ceaf591
git archive ceaf591 | tar -x -C /tmp/vws-fixtures-ceaf591
cp testdata/upgrade/ceaf591/generate_test.go.txt \
   /tmp/vws-fixtures-ceaf591/internal/backend/grpcclient/upgrade_generate_test.go
cd /tmp/vws-fixtures-ceaf591
VWS_UPGRADE_FIXTURES="$OLDPWD/testdata/upgrade/ceaf591" \
   go test ./internal/backend/grpcclient -run '^TestGenerateUpgradeFixtures$' -count=1
```

Without `VWS_UPGRADE_FIXTURES` the generator skips. CI never runs it.

## Current test

`internal/backend/grpcclient/upgrade_test.go` decodes the three label files and
`internal/cloud/upgrade_test.go` decodes the idempotency record. The first test
replays the saved operation id and prunes the held map. Changing a label key or
the record value encoding leaves the fixture undecodable, and the test fails.
