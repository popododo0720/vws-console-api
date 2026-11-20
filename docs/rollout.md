# Rolling out a console-api build

The supported resource backends are `fake` and `regions`. The in-process
`-backend=proxmox` mode and its node-local flags (`-region-config`,
`-registration-file`, `-pve-endpoint`, `-pve-ca-file`, `-helper-path`) are
removed. Reach Proxmox through a `vws-region` daemon deployed as
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
bootstrap etcd and credential files. Live verification remains deferred
until phase 1 development is complete, per the owner decision.
