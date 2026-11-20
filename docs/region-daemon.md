# Region daemon

`cmd/vws-region` runs the phase-one read-only Proxmox backend. It serves
regionapi with client certificate verification on `:8443` and operations
on `:8083`. EC2, S3 and console listeners are disabled; phase one exposes
no flags to enable them. The backend lists pool-scoped instances, template
images, volumes, VM snapshots and tags, plus availability zones and instance
types. VPCs and subnets expose bridge inventory; SDN inventory is not yet
served. Key pairs, route tables and volume modifications remain
empty; a Proxmox region has no S3. Templates without a valid SMBIOS UUID are skipped with a warning;
images use the template name and description, with root size when the boot
disk configuration supplies it.

```sh
vws-region -config /etc/vws/region.yaml -region <name>
```

The daemon is the only process that sends Proxmox resource requests to PVE.
console-api has no in-process Proxmox backend (`-backend` is `fake` or
`regions`); it reaches the daemon over regionapi through `-backend regions`.
The one exception is the admin Proxmox connection test, which makes read-only
PVE checks (TLS, version, cluster, privileges) from console-api itself.

`-region` names the one region this instance serves; it is required and a
registration for any other region is refused with 400. The daemon talks to
PVE over the API only and needs no sudo and no `/etc/pve`. The default PVE
origin is `https://127.0.0.1:8006`, verified with `/etc/pve/pve-root-ca.pem`;
`-pve-endpoint` and `-pve-ca-file` select another verified endpoint (they
move into the registration in a later step). Region TLS defaults are `/etc/vws/region.crt`,
`/etc/vws/region.key`, and `/etc/vws/global-ca.pem`; the latter must trust
only global client identities. The corresponding flags are
`-tls-cert-file`, `-tls-key-file`, and `-tls-ca-file`.

`/healthz` reports process health. `/readyz` stays 503 during the initial
self-check, then repeats the Proxmox permission, cluster and storage checks
at most once per 2 s; concurrent probes share the check in flight. An
unreachable PVE API or failed self-check returns 503.
Invalid YAML or certificates fail startup; failed self-checks or an unreadable state file fail readiness.
Interrupt and SIGTERM drain both listeners. `/metrics` uses the shared
server exporter; regionapi uses the existing HTTP telemetry middleware.

One daemon serves one cluster, and its in-process locks already serialize
launch placement and the finishing loop, so there is no leader lease. A quorum
gate checks PVE `/cluster/status` every 2 s (standalone: the local node's online
state). Mutations and the launch finishing loop pass only while the last check
found quorum and is at most 5 s old; otherwise they return 503, before any PVE
call. Reads stay available. Status, capabilities and `/metrics`
(`vws_region_api_node{node}`) name `apiNode`, the PVE node the daemon is
connected to, and no leader. A region with quorum reports `available`.
Once the daemon's poller stops (shutdown or a registration reload), the gate
closes for good and a handler still in flight is refused.

### Rollout prerequisites

- Exactly one active `vws-region` per cluster. The gate is not a lock: the
  in-process locks and the TLA model assume a single writer. This release must
  not run with the old per-node layout (a daemon on every PVE node behind a
  VIP). Stop and disable every old per-node daemon, then start the single new
  one. The per-cluster placement belongs to vws-deploy #849; until it ships,
  do not roll this release out through the current per-node packaging.
- Status now carries `apiNode` and no `leader`. The deploy CLI
  (`vws region health`) and the console admin regions view must accept
  `apiNode` before this ships (deploy #849, console #216).

## Registration and state

All daemon state is one file, `registration.json`, in the state directory:
`-state-dir`, default `/var/lib/vws-region/<region>` (systemd
`StateDirectory`). The daemon creates the directory with mode 0700 and the file with mode 0600. It
refuses to start if the directory exists but is a symlink, belongs to another
user or has any group or other access, or if any ancestor up to `/` is not
owned by root or the daemon's user or is writable by group or others without
the sticky bit. On every start it fsyncs the state directory and each ancestor,
and a failed sync fails startup. The file holds the registration and the token
secrets in plain text, like the host's other local secrets (console token,
AWS source keys). There is no helper binary, no sudo, no region KEK and
no snippet file.

The file changes only by a 0600 temporary file in the same directory, fsync
of the file, rename over the target and fsync of the directory; the first
registration relies on the directory entries synced at start. A crash
leaves the old file or the new one, never a partial one. A temporary file
left by a crash is removed at startup and is never read as state. In-process
mutex serializes registrations and reloads; there is no lock file.

After a restart the daemon reads the file and is ready without a new
registration. Before registration, `/readyz` returns 503 with `unregistered`.
A file readable by group or others, or naming another region than `-region`,
fails readiness.

`PUT /internal/v1/registration` requires the global client's mTLS certificate.
Its JSON fields are `region` (must equal `-region`, otherwise 400),
`cluster_name`, `zones` (letter and node groups), `tokenId`
(`user@realm!name`) and `token` (write-only), plus the optional
`firewallTokenId` and write-only `firewallToken` of the security group token,
and `backupTokenId` and write-only `backupToken` reserved for disk exports.
An omitted secret reuses the stored one only for the same token id. The PVE
self-check runs before anything is written; a failed check leaves the old file.
See [registration rules](rules.md) for size limits and reloads.
No credential value belongs in region.yaml, command arguments or the
environment. Registration decoder errors never echo submitted values.

Optional `sdn_zone` in region.yaml selects an existing PVE SDN zone for
VPC writes when `read_only` is false. Grant SDN.Allocate on that zone and
on /sdn without propagation; startup probes foreign zones and refuses
inherited allocation. Without the key VPC writes are UnsupportedOperation.

Security group writes need the firewall token, for example `vws@pve!firewall`
with a role holding only Sys.Modify and Sys.Audit on /. Without it they are
UnsupportedOperation; the region token never receives Sys.Modify.

The backup token, for example `vws@pve!backup`, uses a `VWSBackup` role
containing only `VM.Backup Datastore.AllocateSpace`, scoped to managed pools
and backup storage. It must differ from both other token ids. Startup requires
VM.Backup on each configured `/pool/<id>` and Datastore.AllocateSpace on a
`/storage/<id>` path, refuses any other privilege (including VM.Allocate), and
refuses backup tokens on read_only regions because a stop-mode export writes
PVE state. The admin API calls its write-only secret `backupTokenSecret`.
Disk export itself is not enabled by registration.

## Non-root loopback stack

Run `go test -race ./internal/backend/proxmox -run TestPVEFakeCommandRegionInventoryAndRestart -count=1`
as a non-root user for the complete pvefake, region daemon and console API
admin lifecycle. It builds the shipped commands, uses loopback listeners,
registers through the console API, verifies all connection diagnostics,
reads health, edits zones twice and deletes the region. It restarts the stack
and repeats with a fresh memory registry and the persisted daemon identity.

For a console e2e job, build `./cmd/pvefake`, `./cmd/vws-region` and
`./cmd/vws-console-api`. Keep the files in an absolute, clean `$ROOT`, owned
by the CI user; the daemon state goes to `$ROOT/state`.
The global `-admin-kek-file` is a base64-encoded 32-byte key.
Use test certificates with the loopback IP in their subject alternative
names, a CA trusted by both peers, and server/client authentication usages.
Keep their private keys at mode 0600.

Start the processes in this order:

1. Start `pvefake -scenario cmd/pvefake/testdata/scenario.yaml -listen 127.0.0.1:0 -ca-file "$ROOT/pve-ca.pem"`.
   Its single stdout line is the ready HTTPS origin; use it as `$PVE`.
2. Write `$ROOT/region.yaml` with `read_only: true` and
   `pools: {project: '123456789012'}`. Start the region:

   ```sh
   vws-region -config "$ROOT/region.yaml" \
     -region pve-test-1 -state-dir "$ROOT/state" \
     -pve-endpoint "$PVE" -pve-ca-file "$ROOT/pve-ca.pem" \
     -tls-cert-file "$ROOT/cert.pem" -tls-key-file "$ROOT/key.pem" \
     -tls-ca-file "$ROOT/ca.pem" \
     -region-addr 127.0.0.1:18443 -ops-addr 127.0.0.1:18083
   ```

   `/healthz` on the ops listener returns 200; `/readyz` returns 503
   `unregistered` until the console registers the region.
3. Start the global API. `-admin-store memory` is for this loopback trial
   only: registrations are lost on restart and it is not recommended for
   production, where etcd is the store:

   ```sh
   vws-console-api -backend regions -admin-store memory \
     -admin-kek-file "$ROOT/admin-kek" \
     -region-mtls-ca-file "$ROOT/ca.pem" \
     -region-mtls-cert-file "$ROOT/cert.pem" \
     -region-mtls-key-file "$ROOT/key.pem" \
     -console-token loopback-token -access-key loopback-key -secret loopback-secret \
     -console-addr 127.0.0.1:18080 -ec2-addr 127.0.0.1:18081 \
     -s3-addr 127.0.0.1:18082 -ops-addr 127.0.0.1:18084 -iam-addr 127.0.0.1:18085
   ```

   Wait for its ops `/readyz` to return 200. Use `Authorization: Bearer
   loopback-token` for console requests. POST `/api/v1/admin/regions`
   with `name: pve-test-1`, `clusterName: test`, `pveApiUrl: $PVE`,
   `caPem` containing `pve-ca.pem`, `tokenId: vws@pve!inventory`,
   `tokenSecret: fake-secret`, `regionEndpoint: https://127.0.0.1:18443`
   and `zones: [{"letter":"a","nodes":["pve1"]}]`.
4. Wait for the region ops `/readyz` to return 200. POST
   `/api/v1/admin/regions/pve-test-1/test` with `{"tokenSecret":"fake-secret"}`;
   all five steps return `PASS`. GET the same region's `/health`, PATCH
   its `zones` using the latest `ETag` as `If-Match`, then DELETE it.
   Stop the processes with SIGTERM. The global registrations disappear
   on restart; the daemon's registration file remains under `$ROOT/state`.
