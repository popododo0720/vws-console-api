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

The daemon is the only process that connects to PVE. console-api has no
in-process Proxmox backend (`-backend` is `fake` or `regions`) and imports no
Proxmox code; it reaches the daemon over regionapi through `-backend regions`.
This includes the admin Proxmox connection test: console-api forwards the
candidate registration (`pveApiUrls`, `caPem`, token id and secret, and the
region's mapped pools) to `POST /internal/v1/connection-test` on the daemon,
and the daemon runs the read-only PVE checks (TLS, version, cluster,
privileges) and returns the four steps. console-api adds the regionapi step.

The route works before the region is registered or ready, so an operator can
test a candidate first. It shares the registration listener, so only a client
with a certificate from the global CA reaches it. It probes only the
addresses in the request, with the registration checks (HTTPS origins, at
most 16, one CA that must sign them) and no redirects; the token goes only
over connections whose server certificate chains to that CA. It GETs only, writes no
file and does not touch the live registration, its state file or the quorum
gate. The token is sent only over this channel, held for the call and never
logged. At most two tests run at once, each within 12 s.

A region that has no daemon yet, such as a new region before install, has
nothing to answer: the test fails the `tls` step with "PVE checks run in the
region daemon, which did not answer" and a classified reason, and skips the
rest. Install and start `vws-region` for the region, then run the test again.

`-region` names the one region this instance serves; it is required and a
registration for any other region is refused with 400. The daemon talks to
PVE over the API only and needs no sudo and no `/etc/pve`. It has no flag for
PVE addresses or a CA: the registration carries `pveApiUrls` (1 to 16 HTTPS
origins of the one cluster) and `caPem`, and the daemon trusts that CA for
every address and never the system roots. It queries all addresses at
registration and refuses the registration if one reports another cluster name
or does not answer. It then keeps one ordered list and one current address and
rotates to the next on failure (see "Endpoint failover" in
`docs/region-layer.md`). A state file written before this change has neither
field and keeps `/readyz` at 503 until the region is registered again with
its token secret. An omitted secret is reused only for the same CA and
addresses the file already holds; a firewall or backup secret follows
the same rule, because every token goes to every address. With two or more addresses every one must
report a cluster row with the registered name; a standalone node is accepted
only as the single address. Region TLS defaults are `/etc/vws/region.crt`,
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
the sticky bit. The path is resolved once (symlinked ancestors are followed),
every component of the resolved path is checked without following symlinks,
and all state I/O uses only the resolved path. Missing directories are created one at a time, each only after its parent passed, so a refused path leaves nothing behind. On every start it fsyncs the state directory and each ancestor,
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

`POST /internal/v1/deregister` (same mTLS requirement, body `{"region": "<name>"}`,
400 for another region) makes the daemon forget the registration. It deletes
`registration.json` and syncs the directory, stops the quorum gate and the
launch finalizer and waits for them, withdraws the region API and reports
`unregistered` on `/readyz`. When it returns, no finalizer write is running or
can start; a request that was already past the gate may still finish. It is
idempotent: a daemon with nothing registered answers 200. A failed removal
changes nothing else and returns 503, so the call can be repeated.

The global API sends it before it removes a region (`DELETE
/api/v1/admin/regions/<name>`). If the daemon cannot be reached the delete
fails with 503 and the region stays registered. To remove a region whose
daemon is gone for good, add `?force=true`. The entry is then removed but the
daemon, if it ever comes back, still holds the PVE token: delete the token in
PVE (`pveum user token remove <user> <token>`). The same applies to the
firewall and backup tokens. Changing `regionEndpoint` does not deregister the
old daemon yet.
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
reads health, edits zones twice and deletes the region; the delete
deregisters the daemon, which removes its state file and reports not ready. It
restarts the stack and repeats from a fresh memory registry and an unregistered
daemon.

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
   with `name: pve-test-1`, `clusterName: test`, `pveApiUrls: ["$PVE"]`,
   `caPem` containing `pve-ca.pem`, `tokenId: vws@pve!inventory`,
   `tokenSecret: fake-secret`, `regionEndpoint: https://127.0.0.1:18443`
   and `zones: [{"letter":"a","nodes":["pve1"]}]`.
4. Wait for the region ops `/readyz` to return 200. POST
   `/api/v1/admin/regions/pve-test-1/test` with `{"tokenSecret":"fake-secret"}`;
   all five steps return `PASS`. GET the same region's `/health`, PATCH
   its `zones` using the latest `ETag` as `If-Match`, then DELETE it. The
   daemon deletes `$ROOT/state/registration.json` and its `/readyz` returns 503
   `unregistered`.
   Stop the processes with SIGTERM. The global registrations disappear
   on restart.
