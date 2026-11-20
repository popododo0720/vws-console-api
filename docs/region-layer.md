# Region layer operations

This page explains how the Proxmox region layer behaves on `main`. Every rule
names the Go tests that pin it. The full rule text and the checks behind it
live in `docs/rules.md`; when the two disagree, `docs/rules.md` wins and this
page is wrong.

This layer runs only inside the `vws-region` daemon. console-api reaches it
through `-backend regions`; it cannot load this code in its own process.

## Endpoint failover

Code: `internal/backend/proxmox/pveclient/endpoints.go`.

- The registration lists 1 to 16 addresses of one cluster. The daemon keeps
  that list in order with one current index and sends each request to the
  current address. A failure rotates the index to the next address, wrapping
  around. There are no health checks beyond the quorum gate.
- A GET moves to the next address after any transport error. Any other method
  moves only when no connection was obtained, that is a dial or TLS handshake
  failure before the first byte of the request. A write that was sent and then
  cut off returns an error and is not sent to another address; the task
  (UPID) and launch-marker reconciliation read PVE to learn the outcome.
- Every address is checked against the registered `caPem` only, under its own
  host name. Redirects are not followed, and a token goes only to an address
  of the registered list.
- Concurrent failures rotate the index once: only a caller that still sees
  the failed address as current moves it.
- A console websocket goes to the address that issued its ticket.
- Each attempt is bounded: connect and TLS handshake 1 s, and a GET with
  another address left to try waits 1 s for response headers. A request starts
  no new attempt on another address after 4 s. A stalled address therefore
  costs about 1 s, not the whole call.
- A write goes to an address only while that address itself has a positive
  quorum result no older than 5 s (the gate marks it). This holds for the first
  attempt and for every pre-connect retry; otherwise the write is not sent and
  the call returns the Unavailable refusal. Moving the index, for example after
  a failed read, therefore never sends a write to an unchecked address. The
  console ticket POST follows the same rule.

Tests: `TestEndpointsRetryOnlyWhatNeverReachedTheServer`,
`TestEndpointsNeverResendASentWrite`,
`TestEndpointsReadAfterCutGoesToTheNextAddress`,
`TestEndpointsUseTheRegisteredAddressesOnly`,
`TestEndpointsDeadAddressWithConcurrentCalls`,
`TestEndpointsAllAddressesDownIsAnError`, `TestNewEndpointsRefusesNonOrigins`,
`TestFailoverSkipsAFirstAddressThatIsDown`,
`TestFailoverNeverResendsAWriteThatWasSent`,
`TestEndpointsWriteNeedsFreshQuorumOfItsOwnAddress`,
`TestEndpointsRetryOfAWriteSkipsAddressesWithoutQuorum`,
`TestEndpointsPinnedRequestNeverFailsOver`,
`TestEndpointsStalledAttemptsAreBounded`,
`TestFailoverKeepsTheConsoleOnTheAddressThatIssuedTheTicket`.

## Quorum gate

Code: `internal/backend/proxmox/quorum.go`.

- There is no lease and no leader. One daemon serves one cluster, and its
  in-process locks already serialize placement and the finishing loop.
- Quorum is read from `/cluster/status` every 2 s with a 2 s timeout. A
  standalone node (no cluster row) counts as quorate while the local node is
  online.
- The check probes each address pinned to it (no failover inside a probe),
  starting at the current one, under its own 2 s timeout, and starts no new
  probe after 4 s. The first address that reports quorum becomes the current
  one and is marked quorate; an address that fails or reports no quorum loses
  its mark. A stalled or minority address is therefore left within one check.
  The gate stays closed when no address has quorum, and `Admit` also refuses
  while the current address has no fresh mark. The freshness time is the start
  of the last probe.
- `Admit` makes no PVE call. It returns `Unavailable` ("region has no
  quorum") until the first check, when the last check found no quorum or
  failed, or when the last check is older than 5 s. Otherwise it admits.
- Mutations pass `Admit` in the region API before dispatch. The launch
  finishing loop calls it before each pass and before each write. Reads never
  pass the gate.
- Status and capabilities report `apiNode`, the node the daemon is connected
  to (the `local` row of `/cluster/status`), and `vws_region_api_node{node}`
  shows it. A region with quorum and a PVE version is `available`.

Tests: `TestQuorumGateStartsClosed`, `TestQuorumGateFreshness`,
`TestQuorumGateClosesWhenQuorumIsLost`, `TestQuorumGateClosesWhenPVEFails`,
`TestQuorumGateStandaloneUsesLocalNode`, `TestQuorumGateReportsAPINode`,
`TestRegionAPIWithoutQuorumRefusesMutationsAndServesReads`,
`TestMutationRegistrationDerivesQuorumGate`,
`TestRegionAPINodeGaugeTracksConnectedNode`,
`TestClusterMetadataFollowsQuorum`, `TestLaunchFinalizerQuorumGate`,
`TestQuorumGateStopsFinalizeWrites`,
`TestGateLeavesAnAddressWithoutQuorumWithinFiveSeconds`,
`TestGateLeavesAnAddressThatIsDown`,
`TestGateWithNoQuorumAnywhereStaysClosedAndTriesEachAddressOnce`,
`TestGateReachesAHealthyAddressPastAStalledOne`,
`TestAdmissionClosesWhenTheIndexMovesToAnUncheckedAddress`,
`TestWriteRetryNeverReachesAnUncheckedAddress`.

## Unavailable and X-Vws-Stale

`Unavailable` (`resource.CodeUnavailable`) means the region couldn't safely
answer right now and a retry may succeed. The region layer returns it when:

- the quorum gate refuses a mutation (see above);
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

`RunInstances` plans every missing index before submitting any clone.
Instances remain pending until finalize is implemented in #772.

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

`RunInstances` writes launch markers atomically with clones, recovers allocated
indexes after restart and submits only missing indexes. Retries return the same
reservation, instance IDs and key-derived format 03 operation. Changed request
fingerprints are refused. User data, extra disks, custom root sizes and network
interfaces remain unsupported by this accept path.
(`TestRunInstancesReplayRestartAndPartial`)

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
| RunInstances | `GET /cluster/nextid`, `POST /nodes/{node}/qemu/{template}/clone` with bound pool and recovery description | `internal/backend/proxmox/launch.go` |
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
