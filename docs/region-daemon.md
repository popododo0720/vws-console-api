# Region daemon

`cmd/vws-region` runs the phase-one read-only Proxmox backend. It serves
regionapi with client certificate verification on `:8443` and operations
on `:8083`. EC2, S3 and console listeners are disabled; phase one exposes
no flags to enable them. The backend currently declares empty inventory.

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

The daemon acquires `/etc/pve/vws/leader` under the helper's named `leader`
mkdir lock. Leases last 20 s and renew every 5 s; quorum checks run every 2 s.
Mutation admission requires fresh quorum and more than 5 s of lease time.
Standalone nodes use the local node's online state for quorum.
The operations exporter exposes `vws_region_leader{node}` and leader changes
are logged through obs. A restarted process waits for its old lease to expire.
This first part of #766 fences followers with 503; one-hop forwarding,
peer client certificates and stale-read headers remain for the next part.

## Registration

Before registration, `/readyz` returns 503 with `unregistered`.
`PUT /internal/v1/registration` requires the global client's mTLS certificate.
Its JSON fields are `region`, `cluster_name`, `zones` (letter and node groups),
`tokenId` (`user@realm!name`) and `token` (write-only).
See [registration rules](rules.md) for size limits, reloads and recovery.
No credential value belongs in region.yaml, command arguments or the
environment. Snapshot decoder errors never echo submitted values.

## Privileged helper

`cmd/vws-region-helper` provides `registration-write`, `token-write` and
`lease-write`, taking contents on stdin (at most 1 MiB) and no path arguments.
`token-read` takes no arguments and returns only the encrypted envelope.
They atomically replace `/etc/pve/vws/registration.json`,
`/etc/pve/priv/vws/pve-token` and `/etc/pve/vws/leader`.
Public identity and lease files use mode 0640 (pmxcfs owns them as root:www-data);
token and snippet files use 0600. Token files contain a versioned AES-256-GCM envelope
authenticated with the raw 32-byte `$CREDENTIALS_DIRECTORY/region-kek`.
The credential must be a root-owned regular file with no group/other access.
With no credential directory, the helper uses `/etc/vws/credentials/region-kek`.
`regionhelper.Open` authenticates and decrypts this format.

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
