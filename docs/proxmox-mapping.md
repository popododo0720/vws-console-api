# Proxmox to AWS mapping

Every AWS id and attribute in a `pve-*` region is computed from Proxmox data
on each read or from the in-memory observation described below. Nothing is
persisted, so a VM made in the Proxmox UI shows up as it is. Each formula below
names the function in
`internal/backend/proxmox/ids.go` (#735) or `tags.go` (#736) that implements
it; those issues pin one input and output pair per formula in a table test.

## Notation

- `H(x)` is `hex(sha256(x))`.
- `a || b` joins the parts with a `\x00` byte between them.
- Every input is lower-cased first.
- An id's hex part is 17 digits, `H(...)[0:17]`, which `resource.Parse`
  accepts and AWS uses.
- `cluster` is the `name` of the `type=cluster` row of `GET /cluster/status`.
  A standalone node has no such row and uses `cluster_name` from its region
  registration. When both exist and differ, the region daemon refuses to
  start, so ids from two clusters can't mix.

## Ids

| Resource | Formula | Proxmox source | Function |
| --- | --- | --- | --- |
| Instance `i-` | `"i-" + H("vws-pve-instance-v1" \|\| cluster \|\| uuid)[0:17]` | `uuid=` of `smbios1` in the VM config | `InstanceID` |
| Instance without uuid | `"i-" + H("vws-pve-instance-fallback-v1" \|\| cluster \|\| vmid \|\| meta.ctime)[0:17]`, `idSource: fallback`; with no `meta` either, `vmid \|\| "nometa"` and `idSource: vmid` | `vmid`, `meta.ctime` of the config | `FallbackInstanceID` |
| Image `ami-` | `"ami-" + H("vws-pve-image-v1" \|\| cluster \|\| uuid)[0:17]` | a VM with `template=1` | `ImageID` |
| Unknown image | `"ami-" + H("vws-pve-image-v1" \|\| cluster \|\| "unknown")[0:17]`, never listed by `DescribeImages` | a VM with no `vws.ami.` tag | `UnknownImageID` |
| Volume `vol-` | `"vol-" + serial` | the drive's `serial` option | `VolumeID` |
| Serial of a VWS volume | `H("vws-pve-volume-v1" \|\| cluster \|\| key \|\| index)[0:17]` | mutation key, volume index | `VolumeSerial` |
| Serial of a VWS root | `H("vws-pve-volume-v1" \|\| cluster \|\| uuid \|\| "root")[0:17]` | instance uuid | `RootVolumeSerial` |
| Disk without serial | `"vol-" + H("vws-pve-volume-v1" \|\| cluster \|\| storage \|\| volname)[0:17]`, `idSource: volname` (a rename changes the id) | storage id and volume name | `VolnameVolumeID` |
| Snapshot `snap-` | `"snap-" + H("vws-pve-snapshot-v1" \|\| cluster \|\| uuid \|\| snapname)[0:17]` | `name` of `GET .../qemu/{vmid}/snapshot` | `SnapshotID` |
| Reservation `r-` | `"r-" + H("vws-pve-reservation-v1" \|\| cluster \|\| key)[0:17]` | tag `vws.r.<17hex>` | `ReservationID` |
| Bridge VPC | `"vpc-" + H("vws-pve-vpc-v1" \|\| cluster \|\| "bridge" \|\| iface)[0:17]` | `GET /nodes/{node}/network?type=any_bridge` | `BridgeVpcID` |
| Bridge subnet | `"subnet-" + H("vws-pve-subnet-v1" \|\| cluster \|\| "bridge" \|\| iface \|\| cidr)[0:17]` | same | `BridgeSubnetID` |
| SDN VPC | `"vpc-" + H("vws-pve-vpc-v1" \|\| cluster \|\| zone \|\| vnet)[0:17]` | `GET /cluster/sdn/vnets` | `SDNVpcID` |
| SDN subnet | `"subnet-" + H("vws-pve-subnet-v1" \|\| cluster \|\| vnet \|\| cidr)[0:17]` | `GET /cluster/sdn/vnets/{vnet}/subnets` | `SDNSubnetID` |
| Security group `sg-` | `"sg-" + H("vws-pve-sg-v1" \|\| cluster \|\| group)[0:17]` | `GET /cluster/firewall/groups` | `SecurityGroupID` |

The VMID is never an input of an instance id, because Proxmox reuses VMIDs.
A clone gets a new `smbios1` uuid from Proxmox, so it's a new instance, as in
AWS. When VWS creates a VM it picks the uuid itself, carries it in the clone's
`description` while `lock=clone`, and writes it to `smbios1` when it
finalizes the VM, so the id is fixed at accept time. A read never writes a
missing uuid. Two rows that compute the same id are both marked
`idSource: collision` (`MarkCollisions`) and raise an alarm.

The bridge VPC named by `default_bridge` is `IsDefault=true` and its subnet
`DefaultForAz=true`. Templates are listed as images, not instances.

## Instance launch time

`DescribeInstances` uses the VWS launch marker's `created` timestamp when
present. Otherwise, including legacy markers without `created`, `launchTime`
is the UTC time of the first successful inventory observation of that VM.
It stays fixed in the existing pool-bound instance snapshot across repeated
reads and offline-node display. Restarting the backend, losing visibility of
the VM, or changing its pool or instance identity starts a new observation.
This is an estimate of creation time, not the exact clone completion time.

The observation uses `GET /cluster/resources?type=vm` and
`GET /nodes/{node}/qemu/{vmid}/config`, already readable with the PVEAuditor
token. It requires no task history, extra privileges or PVE writes.
`meta.ctime` is excluded from launch time because clones can inherit it from
their template; it remains an input to fallback instance IDs.
`TestInventoryLaunchTimeIgnoresInheritedCtime` covers this with pvefake and
an audit-only token, including repeated reads and restart.

## Tags

Proxmox tags allow only `[a-z0-9_][a-z0-9_\-\+\.]*`, without case. A user tag
`key=value` becomes one Proxmox tag:

```text
pve_tag := "vws.t." enc(key) "." enc(value)
enc(s)  := for each byte of the UTF-8 string
             a-z, 0-9, '-'   kept as is
             A-Z             '+' and the lower-case letter
             any other byte  '_' and two lower-case hex digits
```

| Rule | Function |
| --- | --- |
| Encode one user tag as above. | `EncodeTag` |
| Decode a `vws.t.` tag: `+` takes the next letter, `_` the next two hex digits, `.` is only the separator; only the spelling `EncodeTag` writes decodes. | `DecodeTag` |
| Split a VM's `tags` and `description` into user tags and system tags; a key is read once. | `ReadTags` |
| A tag whose encoding is longer than 128 characters goes to the `vws:tags` JSON block of the VM `description` instead, and a key lives in one place only. | `Split`, `WithDescriptionTags` |
| Keys starting with `aws:`, `vws:` or `vws.` are `InvalidParameterValue`. | `EncodeTag` |

Examples: `Name=web-01` is `vws.t.+name.web-01`. `cost:center=R&D` followed
by a space and U+D300 is `vws.t.cost_3acenter.+r_26+d_20_ed_8c_80`. An empty
value `env=` is `vws.t.env.`. The code is a bijection, and the fuzz test
`FuzzTagRoundTrip` holds `decode(encode(k, v)) == (k, v)`.

`DescribeInstances` supplies the PVE VM config's `name` as the EC2 `Name`
tag when no explicit `Name` user tag exists. An explicit `Name` from
either the encoded tags or the description block wins, including an empty
value. Tag keys remain case-sensitive: `name` does not override `Name`.
An unnamed VM gets no synthetic `Name`. This read-time value is not
written to PVE and follows the VM's current name on each successful read.

System tags are never decoded as user tags: `vws.k.`, `vws.f.`, `vws.n.`,
`vws.r.`, `vws.ami.`, `vws.kp.`, `vws.dot.`, `vws.d.`, `vws.vt.`,
`vws.holder` and `vws.live.`. A disk has no tags in Proxmox, so a volume's
tags sit on the VM that holds it as `vws.vt.<serial[0:8]>.<enc key>.<enc
value>`. Snapshot tags are in the snapshot `description`.

## Launch recovery and operations

`RecoverLaunch` reads the bound pool and returns allocated indexes, the expected
count, reservation and operation. Finalized VMs are indexed by
`vws.k.<key[0:24]>`; unfinalized VMs are found through config descriptions.
The full version-1 marker remains after finalize to confirm the full key and
fingerprint and recover UUIDs and count. Tag prefixes alone are insufficient.
The marker UUID determines the instance ID even while PVE still has a temporary
clone UUID. A changed fingerprint is `IdempotencyMismatch`; unrelated keys and
foreign pools are invisible. Replay lasts for the VMs' lifetime.
Config reads run with at most eight requests in flight. Unrelated malformed
markers are logged and skipped; matching corruption remains Unavailable.

Format `03` has exactly 40 lowercase hex digits:
`"03" + action(2) + H("vws-pve-op-launch-v1" || cluster || key)[0:36]`.
Only action `01` (`RunInstances`) is accepted. Clone UPIDs remain internal.
`GetOperation` recomputes this ID from pool-bound markers. It is running while
indexes are missing, any VM is locked, or any VM lacks the four expected replay
tags or final UUID. It succeeds only when all N indexes are finalized.
Finalize publishes the four replay tags together in its last CAS, after resize
and start have succeeded; their presence is the completion record.

Finalize (#772) records failure by a digest-CAS addition of `vws.launch.failed`
to a VM retaining its marker, before cleanup. That carrier must remain until
the operation need no longer be readable. The reader reports failed with a
fixed Conflict error, without exposing PVE diagnostics. Failure overrides
completion; deleting every carrier makes the operation NotFound.

`pveclient.Clone` writes the description with the allocation POST, without a
digest. Later writes use `WriteConfig` (including `WriteConfigTags`) with the
read digest. A stale digest is a conflict and changes nothing; callers must
reread before recomputing a write.
Clone input validation rejects malformed pool IDs and DNS names, and bounds
valid UTF-8 descriptions to 8192 bytes before making any request.

## Project = pool

- A VM's project is its pool, the `pool` field of its `GET /cluster/resources`
  row. A VM is in at most one pool.
- The admin project mapping binds a project to a pool per region. With no
  binding the pool name is the project id.
- A VM in no pool belongs to the region's `default_project`, the admin
  project. Every other project gets `NotFound` for it.
- A nested pool `parent/child` is one pool name in phase 1.
- Moving a VM between pools changes who may see and change it. Only trusted
  Proxmox admins get `Pool.Allocate`.

## Availability zone = node group

- An operator registers each region's zones as node groups (a rack, a power
  feed): `letter` and `nodes`.
- `zoneName` and `zoneId` are `<region><letter>`, so `pve-seoul-1` has
  `pve-seoul-1a`. Region names end in a number so the zone reads well.
- With no zones every node is in `a`. A node in no group is put in `a` with a
  warning.
- A VM's zone follows its current node, so a migration moves it.

## Instance types

- The catalog is region configuration, published by the capability API. The
  default is `resource.InstanceTypes()` plus `vws.2xlarge` (16 vCPU,
  32768 MiB), `vws.4xlarge` (32, 65536) and `vws.8xlarge` (64, 131072). AWS
  aliases such as `t3.micro` keep working.
- `DescribeInstanceTypes` lists only types that fit some node:
  `cores <= maxcpu` and `memory <= maxmem - host_reserve`. On the 4 vCPU,
  8 GB test box that is `vws.small` and `vws.medium`.
- `RunInstances` sets `cores`, `memory` in MiB, `sockets=1` and the region's
  `cpu` model.
- A described VM gets the catalog type with the same vCPU count
  (`cores * sockets`) and memory within 12.5%, the closest memory on a tie.
  Anything else is `custom`.

## Other mappings

Disk size comes from the drive's `size=` option in VM config, readable with
PVEAuditor, and is rounded up to GiB. Storage content supplies optional format
and a size when config size is unavailable. PVE filters VM storage content
by `VM.Config.Disk`, so an audit-only token can receive an empty content list;
this never hides a configured disk. If neither source gives a positive size,
the disk remains listed with size zero (unknown) and a structured warning.
An unavailable format is empty. pvefake applies the same per-VM disk privilege
filter, including privileges inherited from pools.

| AWS | Proxmox |
| --- | --- |
| Region | Cluster |
| Instance state | `running` and `stopped` from `status`; `pending` while `lock=clone` or `create` or while `qmpstatus` is `paused` or `prelaunch`; `stopping` and `shutting-down` while our task runs. A deleted VM is `InvalidInstanceID.NotFound`. |
| AMI | VM template |
| User data, key pair | cloud-init (`sshkeys` and a snippet file) |
| EBS volume, snapshot | VM disk, VM snapshot without RAM state |
| VPC, subnet | SDN VNet and subnet, or one default VPC per bridge or VLAN |
| Security group | Proxmox firewall security group; a VM with its firewall off has none |
| Long-running operation | Proxmox task (UPID), or key-derived format 03 for a launch |
| Console access | `vncproxy` or `termproxy`, relayed by VWS; no Proxmox account is handed out |
