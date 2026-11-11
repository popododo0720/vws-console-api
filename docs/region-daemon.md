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
Invalid configuration, registration or certificates fail startup.
Interrupt and SIGTERM drain both listeners. `/metrics` uses the shared
server exporter; regionapi uses the existing HTTP telemetry middleware.

## Registration boundary before #757

The design stores registration identity in pmxcfs and the encrypted token
under `/etc/pve/priv/vws/`. The registration intake is not wired yet.
This daemon consumes a **decrypted registration
snapshot** at `-registration-file` (default
`/etc/pve/priv/vws/registration.json`) to exercise the daemon independently.
It must be a regular file with no group or other permission bits and
contain one JSON object with `region`, `clusterName`, `tokenId`, and `token`.
`region` is 1-63 lowercase letters, digits or inner hyphens, `clusterName`
1-63 of `[A-Za-z0-9._-]`, and `tokenId` `user@realm!name`.
No credential value belongs in region.yaml, command arguments or the
environment. Snapshot decoder errors never echo submitted values.

This plaintext snapshot is not the production format. #757 replaces it
with the encrypted pmxcfs token reader and the admin registration
identity reader before deployment. Tests use synthetic pvefake
credentials only.

## Privileged helper

`cmd/vws-region-helper` provides `registration-write`, `token-write` and
`lease-write`, taking contents on stdin (at most 1 MiB) and no path arguments.
They atomically replace `/etc/pve/vws/registration.json`,
`/etc/pve/priv/vws/pve-token` and `/etc/pve/vws/lease.json`.
Public identity and lease files use mode 0640 (pmxcfs owns them as root:www-data);
token and snippet files use 0600. Token files contain a versioned AES-256-GCM envelope
authenticated with the raw 32-byte `$CREDENTIALS_DIRECTORY/region-kek`.
The credential must be a root-owned regular file with no group/other access.
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

`regionhelper.Client` invokes the installed helper path directly, with fixed
verbs, stdin contents and a 10 s deadline. The helper reports a generic
failure on stderr and a nonzero exit code; no submitted contents are echoed.
File replacement and deletion can be retried; lock acquisition deliberately
fails on an existing directory. A killed write leaves the old target or the
complete replacement; an orphan temporary file is never read as a target.
Daemon integration is #757, lease leadership is #766, and sudo/systemd
credential delivery and installation are vws-deploy#764.
