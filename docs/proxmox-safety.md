# Proxmox safety rules

## Token roles per phase

VWS calls Proxmox as the user `vws@pve`, which can't log in. Every token has
`privsep=1`, so its rights are the user's rights cut down by the token's own
ACL. Tokens expire after a year and are rotated from the region edit page of
the admin API. The secret is write-only, kept encrypted under
`/etc/pve/priv/vws/` on its own cluster, and never shows up in a log, a
config file, `/metrics` or an API answer.

| Phase | Token | Role | ACL path | Start-up self-check |
| --- | --- | --- | --- | --- |
| 1, read only | `vws@pve!inventory` | built-in `PVEAuditor` | `/`, propagated | The daemon refuses to start if `GET /access/permissions` shows any of `VM.Allocate`, `VM.PowerMgmt`, `VM.Config.*`, `VM.Snapshot`, `VM.Console`, `Permissions.Modify`, `Pool.Allocate`, `Sys.Modify`, `Datastore.Allocate`. With `read_only: true` the mutation paths are off. |
| 2 to 4, mutations | `vws@pve!region` | `VWSRegionOperator`: `VM.Audit VM.Allocate VM.Clone VM.PowerMgmt VM.Config.CPU VM.Config.Memory VM.Config.Disk VM.Config.Network VM.Config.Cloudinit VM.Config.Options VM.Config.HWType VM.Snapshot VM.Console VM.GuestAgent.Audit Pool.Audit` | `/pool/<pool>` for each managed pool | The daemon refuses to start if the token holds a `VM.*` right outside its managed pools (`/` or `/vms`). |
| | same token | `VWSTemplateReader`: `VM.Audit VM.Clone` | the template pool `/pool/vws-images` | |
| | same token | `VWSStorageUser`: `Datastore.Audit Datastore.AllocateSpace` | each configured `/storage/<id>` and the snippets storage | |
| | same token | `VWSNetUser`: `SDN.Use SDN.Audit` | the zones and bridges in use | |
| | same token | `PVEAuditor` | `/` | |
| 5, DR backup | `vws@pve!backup` | `VM.Backup Datastore.AllocateSpace` | managed pools, backup storage | Kept apart from the mutation token. |

Never granted: `Permissions.Modify`, `Pool.Allocate` (moving a pool is an
admin's permission change), `Sys.Modify`, `Datastore.Allocate`, `VM.Migrate`,
`VM.Snapshot.Rollback` and `VM.GuestAgent.Unrestricted`. There's no
`root@pam` token, and VWS never sends `skiplock`.

## The pool check before every mutation

Every mutation in `internal/backend/proxmox` starts by reading the target VM
fresh from `GET /cluster/resources`, never from the cache (#769). It
recomputes the instance id, and a VM that's missing, a template, or in a pool
other than the caller's is `NotFound` with the AWS message, so the answer
doesn't reveal that the VM exists. A volume checks both the holder and the
instance, and a snapshot checks the VM that owns it. An AST test,
`TestEveryMutationChecksPool`, fails on a mutation that skips this call.

A Proxmox admin may move a VM between the check and the call. That window of
a few seconds is accepted, because the token's ACL covers only managed pools
anyway. VWS never calls `PUT /pools`: the only way it puts a VM in a pool is
the `pool` parameter of the clone it makes. Pool moves made by admins are
observed in the audit log and never undone.

## Other guards

- A VM with `protection=1` can't be terminated or have a volume deleted:
  `OperationNotPermitted`.
- A volume holder VM is never started and is hidden from the instance list.
- A node that isn't the leader, or is outside quorum, sends no mutation to
  Proxmox.
- Every Proxmox call has a timeout and bounded retries.
- If any start-up self-check fails (token rights, cluster name, region
  configuration, storages and bridges, snippets content, a writable
  `/etc/pve/vws/`), `/readyz` fails and the node stays out of the VIP.

## Test safety

- CI tests use the fake Proxmox API (`pvefake`, #738) only. No test in CI
  reaches a real Proxmox host.
- Live checks run only on the nested test VM `pve-test-1`. The live runner
  starts only when the region's cluster name is on the allow list
  (`pve-test`), the cluster has one node, the pool `vws-live` exists and the
  region configuration says `live_tests: true`. Production regions never set
  `live_tests`.
- Before it makes a VM the runner checks that `vws-live` holds fewer than two
  VMs, tags each VM `vws.live.<runid>`, and deletes it on success, failure
  and panic alike. Live VMs are 1 GiB `vws.small` instances.
- Development bots get neither PVE tokens nor AWS credentials. Tokens live
  only in the verify runner's systemd credentials, never in a bot workflow's
  secrets. `scripts/guard.sh` refuses a tracked `PVEAPIToken=` or `AKIA` key
  literal.

## AWS credentials

- Only the `vws-aws-proxy` process reads the source AWS credentials, through
  systemd `LoadCredential`. The global API, IAM and console processes don't
  have them.
- Each VWS account is bound to an AWS role ARN and an `ExternalId`. VWS IAM
  policy is the first boundary and the AWS role policy the second.
- Default or example keys are refused at start, and credentials never reach
  a log, an error message or the audit log. Session credentials stay in
  memory and are gone after a restart.
