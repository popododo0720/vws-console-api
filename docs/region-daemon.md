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

The daemon holds `/etc/pve/vws/leader` under the helper's named `leader` mkdir lock: 20 s leases renewed every 5 s,
quorum checked every 2 s and fresh for 5 s (standalone: the local node's online state). Mutations need fresh quorum and
more than 5 s of lease; a restarted process waits for its old lease to expire. `vws_region_leader{node}` and obs logs show
leader changes. This first part of #766 fences followers with 503; forwarding, peer certificates and stale-read headers follow.

## Registration

Before registration, `/readyz` returns 503 with `unregistered`.
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
A retry converges. After success and registration unlock, deletion of a different
previous token is best effort. A busy lock or other cleanup failure produces a
secret-free warning without changing the successful result.
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
