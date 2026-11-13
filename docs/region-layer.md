# Region layer operations

This page explains how the Proxmox region layer behaves on `main`. Every rule
names the Go tests that pin it. The full rule text and the checks behind it
live in `docs/rules.md`; when the two disagree, `docs/rules.md` wins and this
page is wrong.

## Leader lease and quorum

Code: `internal/backend/proxmox/leader.go`.

- The lease is a JSON file at `/etc/pve/vws/leader` holding node, term and
  expiry. It's written under the helper's `leader` mkdir lock.
- The owner renews every 5 s and each write extends the lease to now + 20 s.
- The term only increases when a node takes the lease after it has expired.
  A live lease held by a peer is never taken.
- Quorum is read every 2 s with a 2 s timeout. A check older than 5 s counts
  as no quorum. Without fresh quorum the local node is fenced: it neither
  renews nor acquires, and `Current` reports no leader.
- `Admit` makes no PVE call. It returns `Unavailable` ("region leader
  unavailable") when there is no leader, or when the local node leads with
  5 s or less left. Otherwise it admits locally or names the peer to forward to.
- On shutdown the node re-reads the lease under the lock and sets the expiry
  to now, but only for its own node and term. Release and unlock share a 2 s
  deadline that ignores cancellation. Failures are logged and the loop exits.
  A non-owner, a repeated release or a restarted process writes nothing.
- Leadership changes are logged, and `vws_region_leader{node}` shows the
  current leader.

Tests: `TestLeaderFenceHasNoPVECalls`, `TestLeaderLeaseTakeoverAndRenewal`,
`TestLeaderLoopQuorumAndLogs`, `TestLeaderStandaloneAndLeaseErrors`,
`TestLeaderShutdownReleaseAndTakeover`, `TestLeaderShutdownNonOwner`,
`TestLeaderReleaseRechecksOwnershipUnderLock`,
`TestLeaderShutdownReleaseFailureIsBoundedAndLogged`,
`TestLeaderReleaseUnlocksAfterWriteDeadline`,
`TestLeaderReleaseLockAndReadErrors`,
`TestMutationRegistrationDerivesLeaderGate`,
`TestRegionLeaderGaugeTracksChanges`.

## Unavailable and X-Vws-Stale

`Unavailable` (`resource.CodeUnavailable`) means the region couldn't safely
answer right now and a retry may succeed. The region layer returns it when:

- the leader gate refuses a mutation (see above);
- a PVE read or write fails during a power action ("Proxmox power operation
  unavailable", `TestPowerRefusalsAndFailure`);
- a corrupt detach replay record is found on a VM tagged for the token
  (`TestDetachSkipsCorruptUnrelatedReplay`);
- a pool check can't reach PVE (`TestRegionPoolFailureIsUnavailableWithoutCredentials`).

`X-Vws-Stale: true` says an inventory page came from cached data. The
regionapi client copies the header into `Page.Stale`
(`internal/surface/regionapi/client.go`). The regionset fan-out and kernel
merge it across regions, and the console surface sends it back as a response
header, never as a JSON field (`internal/surface/console/inventory.go`).
Fresh requests and the fake backend omit it. No region daemon code sets the
header on `main` yet, so today it only passes through.

Tests: `TestInventoryStaleHeaderAndPartialSurviveTransport`,
`TestConsoleInventoryMetadata`, `TestFakeInventoryHasNoPartialOrStale`,
`TestInventoryPartialRejectsRawErrors`.

## Scheduler filters and defaults

Code: `internal/backend/proxmox/scheduler.go`. `Schedule` is a pure function
over one `/cluster/resources` snapshot. It reserves capacity only within one
call, so the caller has to serialize planning and creation.

Input checks: a known instance type, a count from 1 to 10, a target storage
and a positive root size, and finite, non-negative capacities.

Filters, per node:

- type `node` and status `online`;
- the template node only, when the template isn't on shared storage;
- the requested zone, where a node outside every declared zone is in zone `a`;
- the target storage must exist on that node;
- free disk must be at least 1.1 x the root size;
- memory must fit within (maxmem - host reserve) x memory overcommit, and
  vCPUs within maxcpu x CPU overcommit. Running guests count; templates don't.

Defaults: policy `spread`, memory overcommit 1, CPU overcommit 4, host
reserve 2048 MiB when unset. `spread` picks the lowest memory use and `pack`
the highest. Ties go to fewer VMs, then the node name. A placement on shared
storage takes the disk from every node sharing it. No fit returns
`InsufficientInstanceCapacity`.

The scheduler isn't called by a create path yet, because `RunInstances` is
unsupported on Proxmox (see the table below).

Tests: `TestScheduleFilters`, `TestSchedulePolicies`,
`TestScheduleBatchAndZones`, `TestScheduleOneNodeCatalogArithmetic`,
`TestScheduleBatchCapacity`, `TestSchedulePureReplay`,
`TestScheduleInvalidInputs`.

## Crash recovery

The region process keeps no operation state of its own. After a restart it
recovers everything from PVE:

- Power actions first look up the VM's own tasks of the same type. A running
  task, or a finished one when the VM is already at the target state, is
  reported instead of being submitted again. A stop is replayed without a
  second submission. (`TestPowerLifecycleAndRestart`)
- Blank volumes reuse the holder VM and the allocated image on retry after a
  restart or an interrupted allocation or config write.
  (`TestVolumeHolderCreateRetryRestartDelete`,
  `TestVolumeCreateRecoversAllocationAfterConfigFailure`)
- Snapshots use deterministic names plus fingerprint and volume markers, so
  a retry finds the snapshot or its task. (`TestSnapshotWritesRestartReplay`,
  `TestSnapshotOperationPublicationWindows`,
  `TestSnapshotReplayTaskFinishesDuringDiscovery`)
- Attach and detach recover after a disk move that happened before tag
  cleanup, and replay detach tokens from the `vws:detach` record.
  (`TestAttachDetachSerialTagsAndRestartReplay`,
  `TestAttachDetachRecoverAfterMoveBeforeTagCleanup`)
- Tag writes retry on a config digest conflict. (`TestTagWritesRoundTripRetryRestart`,
  `TestTagWritesDigestConflict`)

There's no Proxmox launch recovery yet, since `RunInstances` isn't
implemented. The launch marker codec exists and is tested
(`TestLaunchMarkerRecoversFromPVEConfig`), but nothing writes it.

## Console relay

`consolestream.Relay` (`internal/consolestream/relay.go`) copies framed
messages both ways until either side ends or the context expires, then
closes both streams. The browser side (`internal/surface/console`) and the
region side (`internal/surface/regionapi/console.go`) use the same relay.

- The browser never sees PVE tickets, ports or tokens. Handles live in the
  region process only, are single use, expire after five minutes and are lost
  on restart. At most 1024 are pending; a stream lasts at most one hour and a
  message at most 4 MiB. Tickets and upgrades aren't retried.
- Proxmox checks the pool before it proxies and dials, and `read_only`
  disables consoles.
- AWS regions are refused before transport.

Tests: `TestConsoleRelayExpiryReuseAndRestart`,
`TestConsoleCapacityPrecedesBackend`, `TestGlobalConsoleStreamAndRefusals`,
`TestConsoleChecksPoolBeforeProxy`, `TestConsoleRefusesReadOnlyAndInvalidKind`,
`TestConnectionHonorsConsoleMode`.

## Audit log fields

`internal/audit` writes one JSON line per recorded change on its own logger,
separate from the app log. The fields are exactly:

`time, request_id, trace_id, principal_arn, account, region, destination,
service, action, resource_ids, result, operation_id, latency_ms, source_ip`.

Context values never reach the line, and `account` is allowed here even
though the app log forbids it. The kernel (`internal/cloud/audit.go`) records
every mutation once, with the admission destination and the operation id when
there is one. An audit write failure doesn't change the mutation's result.

Tests: `TestRecordWritesTheFixedSchema`, `TestEmptyEntryKeepsEveryField`,
`TestContextValuesNeverReachTheLine`, `TestRecordLeavesTheAppLoggerAlone`,
`TestRecordReturnsAWriteFailure`, `TestEveryKernelMutationAudited`,
`TestAuditRetryRestartReadsAndBoundaries`,
`TestAuditWriteFailurePreservesMutation`, `TestAuditUsesAdmissionDestination`.

## PVE task and Operation mapping

Code: `internal/backend/proxmox/ops.go` and `GetOperation` in `power.go`. An
operation id carries everything needed to find the work again, so no local
table is kept. The layouts are in `docs/rules.md`; in short:

- Async (`01`): node hash, PID, start time, action and instance. It points at
  one PVE task. `GetOperation` reads the task status: running is `running`,
  stopped with `OK` is `succeeded`, any other exit status is `failed` with a
  redacted `Conflict` error. Create and update times come from the task.
- Sync (`02`): action, kind, target id and a hash of the idempotency key. It's
  used when no task runs, for example a start of a running VM, tag writes and
  volume writes. Snapshot creates resolve through their markers.
- An id that doesn't decode, or whose target isn't in the caller's pool, is
  `NotFound`.

Tests: `TestOperationIDGolden`, `TestOperationIDRefusesInvalid`,
`FuzzOperationIDRoundTrip`, `TestPowerLifecycleAndRestart`,
`TestSnapshotOperationPublicationWindows`.

## EC2 action to PVE call

Paths are relative to `/api2/json`. Every mutation first runs the pool guard
(`TestEveryMutationChecksPool`). Instance actions live in `power.go` and
`inventory.go`; `proxmox.go` holds the unsupported stubs.

| EC2 action | PVE call(s) | Source file |
| --- | --- | --- |
| DescribeInstances | `GET /cluster/resources`, `GET /nodes/{node}/qemu/{vmid}/config` | `internal/backend/proxmox/inventory.go` |
| StartInstances | `GET /nodes/{node}/tasks`, `POST /nodes/{node}/qemu/{vmid}/status/start` | `internal/backend/proxmox/power.go` |
| StopInstances | `POST .../status/shutdown` (timeout, forceStop=1), or `POST .../status/stop` when forced | `internal/backend/proxmox/power.go` |
| RebootInstances | `POST .../status/reboot` | `internal/backend/proxmox/power.go` |
| TerminateInstances | `POST .../status/stop` and wait if running, then `DELETE /nodes/{node}/qemu/{vmid}` (purge, destroy-unreferenced-disks) | `internal/backend/proxmox/power.go` |
| RunInstances | none: returns Unsupported | `internal/backend/proxmox/proxmox.go` |
| DescribeVolumes | `GET /nodes/{node}/qemu/{vmid}/config`, `GET /nodes/{node}/storage/{storage}/content` | `internal/backend/proxmox/volumes.go` |
| CreateVolume | `POST /nodes/{node}/qemu` (holder), `POST /nodes/{node}/storage/{storage}/content`, `PUT .../config` | `internal/backend/proxmox/volume_writes.go`, `internal/backend/proxmox/holder.go` |
| DeleteVolume | `PUT .../config`, `PUT .../unlink` | `internal/backend/proxmox/volume_writes.go` |
| ModifyVolume | none: returns Unsupported | `internal/backend/proxmox/proxmox.go` |
| AttachVolume, DetachVolume | `PUT .../config` (tags, digest), `POST .../move_disk` | `internal/backend/proxmox/attachments.go` |
| DescribeSnapshots | `GET .../config`, `GET /nodes/{node}/qemu/{vmid}/snapshot` | `internal/backend/proxmox/snapshots.go` |
| CreateSnapshot | `GET /nodes/{node}/tasks`, `POST /nodes/{node}/qemu/{vmid}/snapshot` | `internal/backend/proxmox/snapshot_writes.go` |
| DeleteSnapshot | none: returns Unsupported | `internal/backend/proxmox/proxmox.go` |
| CreateTags, DeleteTags | `GET .../config`, `PUT .../config` (tags, digest) | `internal/backend/proxmox/tag_writes.go` |

Tests: `TestPowerLifecycleAndRestart`, `TestPowerQueryShapes`,
`TestInventoryPagingAndFailures`, `TestVolumeHolderCreateRetryRestartDelete`,
`TestVolumeDeleteInUseAndForeignPool`, `TestAttachDetachSerialTagsAndRestartReplay`,
`TestSnapshotWritesRestartReplay`, `TestSnapshotRollbackIsForbidden`,
`TestTagWritesRoundTripRetryRestart`, `TestContract`.
