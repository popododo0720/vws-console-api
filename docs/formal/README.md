# Formal models

## Instance lifecycle (`instance.tla`, #881)

`instance.tla` specifies the phase-2 Proxmox lifecycle before mutation
handlers are implemented. Last confirmed against backend commit `bd4b775`
(the read-only backend); the transition contract added here is
`internal/backend/proxmox/lifecycle.go`. This is a design check, not evidence
that the future handlers already implement its guards.

Run `scripts/tla-instance.sh` with Java 11+. The `instance` job in
`.github/workflows/tla.yml` checks the design, every seeded counterexample,
and Go/model table parity. The runner holds the one immutable jar pin;
`scripts/tla-iam.sh` reads it from there, and `scripts/tla-instance_test.sh`
checks that it does.
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
| `QuorumChange`, `Gate` | quorum loss and recovery; every submission checks that quorum was reported recently |
| `Restart`, `Lookup` | the local lookup is lost; PVE markers and UPIDs survive, and the same token can be retried |

| Invariant | Seed that breaks it |
| --- | --- |
| `OneVMPerClientToken`: at most one existing VM per token | `FixReplay=FALSE`: allocate again instead of reusing its marker |
| `AllowedEdges`: every changed state follows the table | `FixStart=FALSE`: stopped goes directly to running |
| `NoOrphanAfterTerminate`: terminated implies no physical VM | `FixDestroy=FALSE`: publish terminated without deleting the VM |
| `MutationsFenced`: every submission had quorum | `FixFence=FALSE`: submit after quorum loss |

Bounds: two VM identities and two tokens, all interleavings, unlimited
retries, task failures, quorum changes and restarts within that finite
state space. A token represents one RunInstances index; multi-instance
reservations need one such key/index pair per VM. UPIDs are abstract
`(VM, task kind)` pairs; repeat attempts are equivalent for these safety
properties. Failed launch tasks retain their marker and use the destroy
path for undo. Failed stop/destroy tasks stay transitional and can retry.
No liveness is claimed under perpetual task failure or absent quorum.
The leader variable was removed with the pmxcfs lease (#1053), so the earlier
count of 11,433 distinct states no longer applies; the model was edited
without a TLC run (no Java in the authoring environment), so CI's `tla` job is
the check.

Assumptions required of the handlers: one region daemon per cluster,
per-VM serialization across restarts, and serialized marker lookup plus clone
submission, with the marker visible before a restarted daemon may allocate.
The model abstracts the five-second freshness window into current quorum;
it does not prove network-delayed POST fencing.
It does not cover pools, fingerprint mismatch, disk preservation,
or guest-initiated changes. Go boundary tests cover invalid table input;
there is no new API input parser here.

Uniqueness counts existing VMs, not historical allocations. The documented
design gap remains: after Terminate removes PVE markers and a restart
loses the daemon-local cache, the same token may launch a new VM. There is no
persistent tombstone in this model. Terminated is a proof state for
successful destroy; the planned Describe API returns NotFound afterward.

No model covers the Proxmox drive-serial/holder DetachVolume path; the Go
tests named in `docs/rules.md` cover it.

The IAM authorize, then read or write model is `iamauth.tla`, described in
`iamauth.md` (#373).
