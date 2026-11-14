# Usage API

`GET /api/v1/usage?from=2026-10-01&to=2026-11-01` requires
`vws:GetUsage` on `*`. It reads only the caller's project. Both dates are
required in YYYY-MM-DD form, with an exclusive end after the start and a
window of at most 366 days. Unknown and duplicate query keys are refused.

The PVE section returns current allocation, not historical
consumption over that window. Each project's `regions` array contains
`region` and `allocation` (`vcpu`, `memoryBytes`, `diskBytes`). Values come
from live `/cluster/resources` VM rows in the mapped pool. Templates are
excluded; holder disks count but holder CPU and memory do not. Unpooled
VMs belong only to the configured default project.

A failed region has `error: "Unavailable"` and no allocation. Registry
failure is a fixed 503. Reads have a five second deadline, retain no
snapshots and write no registry or PVE state. Responses disable caching.

Each project's `aws` array contains one row per mapped AWS account, sorted
by account id: `{"account":"123456789012","amount":"12.34","unit":"USD"}`.
An unmapped project has `aws: []`. A failed account has only `account` and
`error: "Unavailable"`; other accounts and PVE allocation remain available.

Costs are account-wide Cost Explorer `GetCostAndUsage` reads through the
private AWS proxy and the mapped account's project role. The role needs
`ce:GetCostAndUsage`. Requests use `MONTHLY` granularity and `UnblendedCost`
over the inclusive `from` and exclusive `to`. All returned monthly totals
and pages (at most 100) are summed with exact decimal arithmetic; amounts
stay strings and units come from Cost Explorer. Inconsistent or missing
totals are unavailable. AWS calls share a two second budget within the
request's five seconds and make at most two SDK attempts per page for
transient failures. The proxy signs CE for `us-east-1`, independent of allowed inventory
regions, and permits only `GetCostAndUsage` for an explicitly mapped account.
No cost snapshots or credentials are retained by the console. PVE historical
RRD data remains outside this API.
