# Hybrid architecture

VWS puts AWS (public) and Proxmox VE (private) behind one endpoint. The web
console, Terraform, aws-cli and the SDKs all talk to that endpoint with the
AWS API, and the region in each request decides where it goes. Think of
Proxmox Datacenter Manager with AWS added as one more thing to manage, and
the AWS API as the common language.

```text
  console / Terraform / aws-cli / SDK          (one endpoint)
                     |
     +---------------v-------------------------------------+
     | global layer                                        |
     |  router | IAM | inventory | console | audit log      |
     +----+-------------------+-------------------------+--+
          | pve-*             | pve-*                   | any other region
          v                   v                         v
   region layer         region layer             AWS forwarding proxy
   (every PVE node)     (every PVE node)         (verify, authorize, re-sign)
          |                   |                         |
   Proxmox cluster      Proxmox cluster                 AWS
```

## Principles

1. VWS keeps no state. Proxmox and AWS are the source of truth. IAM is the
   one exception, along with the operator registry (regions, AWS accounts,
   project mappings), and both live in one etcd. A short read cache is a
   copy only: nothing decides ownership or rebuilds a resource from it.
2. A region is a destination. One Proxmox cluster is one `pve-*` region.
   AWS regions keep their AWS names.
3. A VM made in the Proxmox UI simply shows up. There's no import step and no
   side table, because every id is computed by rule
   (`docs/proxmox-mapping.md`). VMIDs get reused, so no id is built from one.
4. Features differ per region. A per-region capability API decides both what
   the console greys out and what the API answers: an unsupported mutation is
   an AWS-shaped `UnsupportedOperation`, and an unsupported read is an empty
   answer, so Terraform's refresh still works.
5. Kubernetes is retired. No cluster, CRDs, kubestore or Helm path. The
   deployment unit is a `.deb` with systemd units.

## Global layer

- **Router**: reads the region from the SigV4 credential scope. `pve-*` goes
  to that region's layer, a registered AWS region goes to the forwarding
  proxy, and anything else is refused.
- **IAM**: users, policies, access keys, STS and MFA, served by vws-iam with
  its store on etcd.
- **Inventory and console**: reads every region and shows one view. Its cache
  is a copy, never the source.
- **Audit log**: records every mutation sent to either side.
- **Admin API**: operators register Proxmox regions and AWS accounts and map
  projects to pools. Admins only, by IAM policy; secrets are write-only and
  stored encrypted.

## Proxmox region layer

- A `.deb` on every PVE node behind one VIP. Any node answers a read the same
  way.
- One leader makes every mutation (placement included). A node outside the
  cluster quorum refuses mutations.
- The PVE API may be called on any node in the cluster; a dead node is
  replaced by another.
- Proxmox has no placement scheduler, so the region layer picks a node for
  `RunInstances` from each node's free CPU, memory and storage.
- The `proxmox` backend runs here, so PVE tokens never leave the cluster. The
  global layer reaches it through the `regions` backend.

## AWS forwarding proxy

It checks the caller's VWS key and IAM policy, then assumes the account's
IAM role and re-signs the request with SigV4. The body is passed through
unread, so any AWS service works, and users never hold AWS keys. The proxy is
its own process and the only one that reads the source AWS credentials.

## Backends in this repo

| `-backend` | Role |
| --- | --- |
| `fake` | In-memory, for tests and local runs. |
| `regions` | The global layer: picks a region per request and sends it to that region layer or to AWS. |
| `proxmox` | The region layer: one Proxmox cluster through its API. |

With `-backend=regions -iam=grpc`, key pair create, import, delete and
describe actions use vws-iam in the caller's region, with no regionapi call.
The global layer generates private keys locally and imports only public
material, preserving EC2 PEM/PPK formats and fingerprints. A missing launch
key returns `InvalidKeyPair.NotFound` before contacting a region. Inline
public keys and Proxmox cloud-init `sshkeys` still await #771 and the rest
of #779. Without gRPC IAM, key mutations and keyed launches are unsupported;
key pair inventory keeps the regional read path.

`grpc` (vws-compute, vws-network and vws-storage on Kubernetes) is the old
path. It stays only until `regions` and `proxmox` replace it (#755) and is not
the production path.

## Phases

1. One read-only inventory and console for both sides.
2. Daily work: create, start, stop, delete, snapshot, console access.
3. One sign-in and one permission model (pool = project, AWS AssumeRole).
4. The AWS-compatible API for Proxmox, and the AWS forwarding proxy.
5. Cold DR, cost and usage, VPC and security groups.

See `docs/proxmox-mapping.md` for how Proxmox objects become AWS resources
and `docs/proxmox-safety.md` for tokens, the pool check and test safety.
