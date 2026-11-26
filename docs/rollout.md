# Rolling out a console-api build

The supported resource backends are `fake` and `regions`. The in-process
`-backend=proxmox` mode and its node-local flags (`-region-config`,
`-registration-file`, `-pve-endpoint`, `-pve-ca-file`, `-helper-path`) are
removed. The `vws-region` daemon has no helper either: `-helper-path`,
`-helper-root`, `-registration-file`, `-pve-endpoint` and `-pve-ca-file` are
gone. Its PVE addresses and CA come from the registration (`pveApiUrls`,
`caPem`), and its state is one 0600 file under `-state-dir`.

Upgrading stored data. Etcd records: a registry record with the old single
`pveApiUrl` loads as a one-address list and is rewritten on its next edit; an
edit also needs a `caPem`, which is now required. Daemon state files: one
written before this change has no addresses or CA, so `/readyz` stays 503
until the region is registered again with an explicit `tokenSecret`. The
daemon reuses a stored secret only when the registration keeps the same
`caPem` and only addresses it already holds, so a legacy file, a changed CA
or a new address needs the secret in the request and otherwise gets 400
before any PVE request. This holds for the firewall and backup secrets too:
the daemon fails over between addresses, so every token can reach every
registered address.

Rollout prerequisite, separate from the read migration above: the clients
that write regions must send `pveApiUrls` before anyone re-saves a region.
The deploy CLI (`vws region add/edit`, vws-deploy #850, `--pve-api-url`
repeated) and the console region form (vws-console #216) still send
`pveApiUrl`, which this API now refuses with 400. Upgrade them first.

Reach Proxmox through a `vws-region` daemon deployed as
`docs/region-daemon.md` describes today, and register it with the admin API.
Running one daemon per Proxmox cluster on the global host is follow-up work
(#1053 and later).
The Kubernetes compute, storage and network backend is removed in #784.
Its ConfigMap launch records and detach-label reservation rollout rules
do not apply to current builds. The historical detach model is
removed; Git history keeps it.

Before upgrading an installation, remove the retired backend selection,
compute/storage/network address flags and Kubernetes launch-store flags
from its service configuration. Select the appropriate backend described in
`docs/hybrid.md`. Existing Kubernetes resource state is not imported into
Proxmox or AWS by changing this process's backend.

IAM remains independent: installations using `-iam=grpc` keep their vws-iam
endpoint and TLS configuration. The resource backend removal does not
replace the IAM service or move its users, keys or sessions.

Run the local build, race tests and lint checks before publishing. Deployment
and rollback must preserve the selected region configuration, registration,
bootstrap etcd and credential files. A `vws-region` rolled back to a release
before cold DR keeps serving its registration, refuses pushes with DR
settings and leaves `dr.json` in place; delete that file or revoke the PBS
token after a permanent rollback (`docs/region-daemon.md`, "Rollback"). Live verification remains deferred
until phase 1 development is complete, per the owner decision.
