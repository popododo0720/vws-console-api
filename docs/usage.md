# Usage API

`GET /api/v1/usage?from=2026-10-01&to=2026-11-01` requires
`vws:GetUsage` on `*`. It reads only the caller's project. Both dates are
required in YYYY-MM-DD form, with an exclusive end after the start and a
window of at most 366 days. Unknown and duplicate query keys are refused.

This first part of #800 returns current PVE allocation, not historical
consumption over that window. Each project's `regions` array contains
`region` and `allocation` (`vcpu`, `memoryBytes`, `diskBytes`). Values come
from live `/cluster/resources` VM rows in the mapped pool. Templates are
excluded; holder disks count but holder CPU and memory do not. Unpooled
VMs belong only to the configured default project.

A failed region has `error: "Unavailable"` and no allocation. Registry
failure is a fixed 503. Reads have a five second deadline, retain no
snapshots and write no registry or PVE state. Responses disable caching.

AWS Cost Explorer costs through the project role and PVE historical RRD
data remain for the next part. There is no AWS section in this part.
