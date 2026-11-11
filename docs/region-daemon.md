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
self-check and repeats the Proxmox permission, cluster and storage checks
on every probe. An unreachable PVE API or failed self-check returns 503.
Invalid configuration, registration or certificates fail startup.
Interrupt and SIGTERM drain both listeners. `/metrics` uses the shared
server exporter; regionapi uses the existing HTTP telemetry middleware.

## Registration boundary before #757

The design stores registration identity in pmxcfs and the encrypted token
under `/etc/pve/priv/vws/`. The registration intake, KEK envelope and root
helper do not exist yet. This daemon consumes a **decrypted registration
snapshot** at `-registration-file` (default
`/etc/pve/priv/vws/registration.json`) to exercise the daemon independently.
It must be a regular file with no group or other permission bits and
contain one JSON object with `region`, `clusterName`, `tokenId`, and `token`.
No credential value belongs in region.yaml, command arguments or the
environment. Snapshot decoder errors never echo submitted values.

This is a plaintext phase-one boundary, not encrypted credential storage.
Do not use it as the production registration format. #757 must replace
this boundary with the encrypted pmxcfs token reader/helper and the
admin registration identity reader before deployment. Kubernetes Secrets
do not participate in the region daemon. Tests use synthetic pvefake
credentials and private temporary snapshots only.
