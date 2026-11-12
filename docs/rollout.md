# Rolling out a console-api build

The supported resource backends are `fake`, `regions` and `proxmox`.
The Kubernetes compute, storage and network backend is removed in #784.
Its ConfigMap launch records and detach-label reservation rollout rules
do not apply to current builds. The historical detach model remains in
`docs/formal/README.md` with its original code mapping pinned in Git history.

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
