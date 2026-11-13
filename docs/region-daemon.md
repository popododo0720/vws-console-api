# Region daemon

`cmd/vws-region` runs the phase-one read-only Proxmox backend. It serves
regionapi with client certificate verification on `:8443` and operations
on `:8083`. EC2, S3 and console listeners are disabled; phase one exposes
no flags to enable them. The backend lists pool-scoped instances, template
images, volumes, VM snapshots and tags, plus availability zones and instance
types. VPCs and subnets expose bridge inventory; SDN inventory is not yet
served. Key pairs, route tables, volume modifications and S3 inventory remain
empty. Templates without a valid SMBIOS UUID are skipped with a warning;
images use the template name and description, with root size when the boot
disk configuration supplies it.

```sh
vws-region -config /etc/vws/region.yaml
```

The default PVE origin is `https://127.0.0.1:8006`, verified with
`/etc/pve/pve-root-ca.pem`. `-pve-endpoint` and `-pve-ca-file` select another
verified endpoint. Region TLS defaults are `/etc/vws/region.crt`,
`/etc/vws/region.key`, and `/etc/vws/global-ca.pem`; the latter must trust
only global client identities. The corresponding flags are
`-tls-cert-file`, `-tls-key-file`, and `-tls-ca-file`.

`/healthz` reports process health. `/readyz` stays 503 during the initial
self-check, then repeats the Proxmox permission, cluster and storage checks
at most once per 2 s; concurrent probes share the check in flight. An
unreachable PVE API or failed self-check returns 503.
Invalid YAML or certificates fail startup; failed self-checks or shared files fail readiness.
Interrupt and SIGTERM drain both listeners. `/metrics` uses the shared
server exporter; regionapi uses the existing HTTP telemetry middleware.

The daemon holds `/etc/pve/vws/leader` under the helper's named `leader` mkdir lock: 20 s leases renewed every 5 s,
quorum checked every 2 s and fresh for 5 s (standalone: the local node's online state). Mutations need fresh quorum and
more than 5 s of lease; a restarted process waits for its old lease to expire. `vws_region_leader{node}` and obs logs show
leader changes. This first part of #766 fences followers with 503; forwarding, peer certificates and stale-read headers follow.

## Registration

Before registration, `/readyz` returns 503 with `unregistered`.
When registration.json names a token file that is absent or unreadable, for
example on a node that still has the unsuffixed `pve-token` layout, `/readyz`
returns 503 and the daemon logs `region not ready` with reason
`registration token unreadable`. There is no automatic
migration: re-register the region with its token (a PUT that includes
`token`), which writes `pve-token.<fp>` and the matching identity without a
restart.
`PUT /internal/v1/registration` requires the global client's mTLS certificate.
Its JSON fields are `region`, `cluster_name`, `zones` (letter and node groups),
`tokenId` (`user@realm!name`) and `token` (write-only).
See [registration rules](rules.md) for size limits, reloads and recovery.
No credential value belongs in region.yaml, command arguments or the
environment. Snapshot decoder errors never echo submitted values.

## Privileged helper

`cmd/vws-region-helper` provides `registration-write` and `lease-write`,
taking contents on stdin (at most 1 MiB) and no arguments.
`token-write <fp>`, `token-read <fp>` and `token-delete <fp>` require a full
lowercase SHA-256 fingerprint matching `^[0-9a-f]{64}$`, checked by both
helper and client before exec. Token files are
`/etc/pve/priv/vws/pve-token.<fp>`. token-write refuses stdin whose hash
differs and seals only that file; token-read returns only its encrypted
envelope. token-delete acquires the registration lock across the identity check
and removal, refuses the current fingerprint, and releases its lock on success
or error. A busy lock refuses deletion without removing any file or that lock;
an absent inactive file is already deleted.
Identity and lease writes atomically replace `/etc/pve/vws/registration.json`
and `/etc/pve/vws/leader`.
Public identity and lease files use mode 0640 (pmxcfs owns them as root:www-data);
token and snippet files use 0600. Token files contain a versioned AES-256-GCM envelope
authenticated with the raw 32-byte `$CREDENTIALS_DIRECTORY/region-kek`.
The credential must be a root-owned regular file with no group/other access.
With no credential directory, the helper uses `/etc/vws/credentials/region-kek`.
`regionhelper.Open` authenticates and decrypts this format.

Registration runs the PVE self-check, acquires the registration lock, writes
the candidate token, then commits by renaming registration.json. That rename
is the only commit point. There are no compensation writes: a helper failure,
including a nonzero exit after rename, leaves a matching old or new pair.
A retry converges. After a confirmed commit and registration unlock, deletion of a different
previous token is best effort. A busy lock or other cleanup failure produces a
secret-free warning without changing the successful result.
After a registration-write error, the writer re-reads identity under the lock;
if the candidate fingerprint committed, it attempts cleanup and returns the error.
An omitted token is read by the stored fingerprint, verified and self-checked;
only the identity is written. Readers select the named file and verify its
content hash. If an old token was deleted during rotation, the reader re-reads
identity once and retries only when the fingerprint changed. Missing or
mismatched pairs fail readiness and serving until repaired.
`TestRegionDaemonReadsRestartAndReadiness` enforces pre-commit and after-rename
failures, retry, rotation, failed candidates, reader races, torn pairs and
recovery. `TestTokenFingerprintGrammar`, `TestTokenWriteEncrypted` and
`TestTokenReadAndCredentialFallback` enforce the helper contract.
`TestTokenDeleteSerializesRegistration` enforces deletion/publication
serialization, busy-lock refusal and lock release after success or refusal.

`lock NAME` uses mkdir under `/etc/pve/priv/lock/vws-region/`; a duplicate
lock fails. `unlock NAME` removes an empty directory; an absent lock succeeds.
Names are 1-64 letters, digits, `_` or `-`, starting with a letter or digit.
`snippet-write NAME` and `snippet-delete NAME` operate only on
`vws-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx-user.yaml` with lowercase hex digits.
The snippet directory is one absolute, clean path in the fixed text file
`/etc/vws/region-helper-snippets`, root-owned and not group/other writable.
This small config avoids granting the caller a directory-selection flag.
The configured directories must already exist and be administered by root.
Final symlinks are refused; operations use an open directory root.

`regionhelper.Client` invokes `sudo -n /usr/lib/vws/vws-region-helper`, with fixed
verbs, stdin contents and a 10 s deadline. The helper reports a generic
failure on stderr and a nonzero exit code; no submitted contents are echoed.
File replacement and deletion can be retried; lock acquisition deliberately
fails on an existing directory. A killed write leaves the old target or the
complete replacement; an orphan temporary file is never read as a target.
Daemon integration is #757, lease leadership is #766, and sudo/systemd
credential delivery and installation are vws-deploy#764.

## Non-root loopback stack

Run `go test -race ./internal/backend/proxmox -run TestPVEFakeCommandRegionInventoryAndRestart -count=1`
as a non-root user for the complete pvefake, region daemon and console API
admin lifecycle. It builds the shipped commands, uses loopback listeners,
registers through the console API, verifies all connection diagnostics,
reads health, edits zones twice and deletes the region. It restarts the stack
and repeats with a fresh memory registry and the persisted daemon identity.

For a console e2e job, build `./cmd/pvefake`, `./cmd/vws-region`,
`./cmd/vws-region-helper` and `./cmd/vws-console-api`. Keep the following
files and directories in an absolute, clean `$ROOT`, owned by the CI user:

```text
etc/pve/vws/
etc/pve/priv/vws/
etc/pve/priv/lock/vws-region/
etc/vws/credentials/region-kek
etc/vws/region-helper-snippets
snippets/
```

The helper KEK contains 32 raw bytes with mode 0600.
`etc/vws/region-helper-snippets` is a non-writable-by-others text file
containing the absolute path `$ROOT/snippets`. `CREDENTIALS_DIRECTORY`,
when set, overrides the rooted KEK path for both daemon and helper.
The global `-admin-kek-file` is a separate base64-encoded 32-byte key.
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
     -registration-file "$ROOT/etc/pve/vws/registration.json" \
     -helper-path "$BIN/vws-region-helper" -helper-root "$ROOT" \
     -pve-endpoint "$PVE" -pve-ca-file "$ROOT/pve-ca.pem" \
     -tls-cert-file "$ROOT/cert.pem" -tls-key-file "$ROOT/key.pem" \
     -tls-ca-file "$ROOT/ca.pem" \
     -region-addr 127.0.0.1:18443 -ops-addr 127.0.0.1:18083
   ```

   `/healthz` on the ops listener returns 200; `/readyz` returns 503
   `unregistered` until the console registers the region.
3. Start the global API:

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
   on restart; the daemon's encrypted token and identity remain under `$ROOT`.

`-helper-root` requires `-helper-path`; both daemon and helper refuse the
override when running as root, and reject empty, relative or unclean roots.
The daemon sets `VWS_REGION_HELPER_ROOT` only on its direct helper child.
The installed sudo invocation receives no root override. For a standalone
helper smoke test, set `VWS_REGION_HELPER_ROOT="$ROOT"` explicitly.
Without it the production paths and uid 0 credential ownership stay unchanged.
