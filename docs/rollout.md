# Rolling out a console-api build

vws-deploy pins the console-api image in `charts/vws/values.yaml`
(`services.console-api.imageTag`). This page covers moving that pin to a
newer build. It is for the DetachVolume label reservation (#332). The
cross-service pin rules are in vws-deploy `docs/image-pins.md`.

## Why the reservation is safe on a rollout

A client-token `DetachVolume` needs one instance label for its operation id.
Its first write holds that label with a `detachOpPending` binding, and the
second write saves the id in it (`docs/rules.md`, the `DetachVolume` client
token rule).

- **No overlap.** vws-deploy renders console-api as one replica with strategy
  `Recreate`, so the old pod stops before the new one starts. Its render
  check refuses any other replica count or strategy (vws-deploy
  `scripts/check_render.py` R4, tested in `tests/vws/render.test.sh`,
  "check_render refuses maxSurge 1"). Two builds never write labels at the
  same time.
- **If builds did overlap.** A build before `99c95e3` (#327) does not know
  the reservation, but it copies the stored binding over and counts it at
  compute's 64 labels, so its tag write is refused rather than taking the
  label. `TestAnOldReplicaCannotTakeAPendingOperationIDsLabel`
  (`internal/backend/grpcclient/detach_rollout_test.go`) proves it, and it
  fails when the binding is only counted, not stored.

A build from `99c95e3` (#327) up to but not including `a17a090` (#367)
counts the reservation without storing it. Next to a build before #327 it
would leave the label free to take, which is the #332 failure. It is never
a rollout target.

## Steps

1. Check that the target build stores the binding. In a clone of this
   repository:

   ```sh
   git merge-base --is-ancestor a17a090 <target commit> && echo ok
   ```

   Every commit on `main` since `a17a090` (2026-10-24) passes. A target that fails is not
   used.

2. Check the cross-service rules in vws-deploy `docs/image-pins.md` and move
   any other pin they name in the same PR.

3. Move `services.console-api.imageTag` in vws-deploy. Do not change the
   replica count or the strategy; R4 refuses the render if you do.

4. After the rollout, the Deployment is one replica, `Recreate`, on the new
   image:

   ```sh
   kubectl -n <release namespace> get deployment console-api \
     -o jsonpath='{.spec.replicas} {.spec.strategy.type} {.spec.template.spec.containers[0].image}'
   ```

   It prints `1 Recreate ghcr.io/popododo0720/vws/console-api:sha-<target>`.

## What does not need a step

No compatibility gate and no two-phase rollout. The stored binding is a real
label that every build counts, and `Recreate` leaves no window where two
builds run.
