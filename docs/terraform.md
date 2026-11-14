# Terraform and aws-cli through one endpoint

Every client talks to one VWS endpoint (`docs/hybrid.md`). The region in the
SigV4 credential scope picks the destination: a `pve-*` region is served by
that Proxmox region layer, any other region is re-signed and forwarded to AWS
by the AWS proxy (`docs/aws-proxy.md`). The examples use
`https://vws.example.com` for the endpoint, `pve-seoul-1` for a Proxmox region
and `ap-northeast-2` for an AWS region. Credentials are VWS access keys; AWS
keys are never handed to users.

## Terraform provider blocks

Use the unmodified `hashicorp/aws` provider with one alias per destination.
Both aliases point at the same VWS endpoint.

<!-- terraform-provider: pve -->
```hcl
provider "aws" {
  alias                       = "pve"
  region                      = "pve-seoul-1"
  max_retries                 = 5
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  skip_region_validation      = true

  endpoints {
    ec2 = "https://vws.example.com"
    sts = "https://vws.example.com"
    iam = "https://vws.example.com"
  }

  default_tags {
    tags = {
      "vws-compat" = "run-1"
    }
  }
}
```

The `pve` block has the provider settings of the Proxmox compatibility
profile, `tests/compat/terraform-pve/main.tf` in vws-deploy, with example
values in place of its variables (`var.region`, `var.ec2_endpoint`,
`var.run_id`) and the `alias` added. That profile has only this block.
`skip_region_validation` is required because `pve-*` is not an AWS region;
the other `skip_*` settings stop the provider from calling AWS metadata and
account APIs. The `vws-compat` default tag marks the compatibility run; drop
or rename it in your own configuration. A pve region serves only the
resources listed in the action table below, which the profile covers with
`aws_instance`, `aws_ebs_volume` and `aws_volume_attachment`.

<!-- terraform-provider: aws -->
```hcl
provider "aws" {
  alias  = "aws"
  region = "ap-northeast-2"

  endpoints {
    ec2 = "https://vws.example.com"
    sts = "https://vws.example.com"
    iam = "https://vws.example.com"
  }
}
```

The `aws` block is the AWS alias of the owner design (section 5). It also
sends STS and IAM to VWS, because VWS serves both globally and AWS STS would
reject a VWS access key. Any other AWS service the configuration uses needs
its endpoint set to the same VWS address, or the provider calls AWS directly
with VWS keys and fails.

Choose the destination per resource:

```hcl
resource "aws_instance" "on_proxmox" {
  provider      = aws.pve
  ami           = "ami-0123456789abcdef0"
  instance_type = "vws.small"
}

resource "aws_instance" "on_aws" {
  provider      = aws.aws
  ami           = "ami-0fedcba9876543210"
  instance_type = "t3.micro"
}
```

## aws-cli

```sh
# Proxmox region
aws --endpoint-url https://vws.example.com --region pve-seoul-1 ec2 describe-instances
aws --endpoint-url https://vws.example.com --region pve-seoul-1 ec2 run-instances \
  --image-id ami-0123456789abcdef0 --instance-type vws.small --count 1

# AWS region through the same endpoint
aws --endpoint-url https://vws.example.com --region ap-northeast-2 ec2 describe-instances
aws --endpoint-url https://vws.example.com --region ap-northeast-2 sts get-caller-identity
```

## Actions in a pve region

The tables list the capability document of a writable Proxmox region
(`resource.RegionCapabilities`, returned by
`internal/backend/proxmox` `RegionCapabilities`). A region with
`read_only: true` in `region.yaml` declares every mutation unsupported with
reason code `ReadOnly`. `TestTerraformDocMatchesCapabilities` fails when a
table here differs from the generated document.

The kernel answers a mutation the document marks unsupported (or omits) with
`UnsupportedOperation` before the backend, and a read marked `empty` with an
empty result. An action this process does not know is `InvalidAction` in
every region. When the global layer has IAM configured, key pair actions are
answered by IAM there and never reach the region.

Served actions (`partial` names what is left out):

<!-- capability-table: served -->
| Action | State | Reason code | Reason |
| --- | --- | --- | --- |
| `ec2:AttachVolume` | supported | | |
| `ec2:CreateSnapshot` | supported | | |
| `ec2:CreateTags` | partial | `InstanceVolumeTags` | instances and volumes only; volume tags require at most 128 encoded characters |
| `ec2:CreateVolume` | partial | `NoSnapshotSource` | blank volumes only; volume tags must encode within 128 bytes |
| `ec2:DeleteTags` | partial | `InstanceVolumeTags` | instances and volumes only; volume tags require at most 128 encoded characters |
| `ec2:DeleteVolume` | supported | | |
| `ec2:DescribeAddresses` | empty | | |
| `ec2:DescribeAvailabilityZones` | supported | | |
| `ec2:DescribeImages` | supported | | |
| `ec2:DescribeInstances` | supported | | |
| `ec2:DescribeKeyPairs` | empty | | |
| `ec2:DescribeRegions` | supported | | |
| `ec2:DescribeRouteTables` | empty | | |
| `ec2:DescribeSecurityGroups` | empty | | |
| `ec2:DescribeSnapshots` | supported | | |
| `ec2:DescribeSubnets` | supported | | |
| `ec2:DescribeTags` | supported | | |
| `ec2:DescribeVolumes` | supported | | |
| `ec2:DescribeVolumesModifications` | empty | | |
| `ec2:DescribeVpcs` | supported | | |
| `ec2:DetachVolume` | partial | `StoppedInstance` | detach requires a stopped instance; config hot-unplug to unused disks is not supported |
| `ec2:RebootInstances` | supported | | |
| `ec2:RunInstances` | partial | `LaunchDefaults` | user data, extra disks and custom root sizes are not supported |
| `ec2:StartInstances` | supported | | |
| `ec2:StopInstances` | supported | | |
| `ec2:TerminateInstances` | partial | `RetainedDisks` | retained disks require holder support |
| `vws:OpenConsole` | supported | | |

Unsupported actions (`UnsupportedOperation`):

<!-- capability-table: unsupported -->
| Action | Reason code | Reason |
| --- | --- | --- |
| `ec2:AllocateAddress` | `ReadOnly` | read-only |
| `ec2:AssociateAddress` | `ReadOnly` | read-only |
| `ec2:AuthorizeSecurityGroupIngress` | `ReadOnly` | read-only |
| `ec2:CreateKeyPair` | `ReadOnly` | read-only |
| `ec2:CreateSecurityGroup` | `ReadOnly` | read-only |
| `ec2:CreateSubnet` | `ReadOnly` | read-only |
| `ec2:CreateVpc` | `NoSDNZone` | no sdn_zone configured |
| `ec2:DeleteKeyPair` | `ReadOnly` | read-only |
| `ec2:DeleteSecurityGroup` | `ReadOnly` | read-only |
| `ec2:DeleteSnapshot` | `ReadOnly` | read-only |
| `ec2:DeleteSubnet` | `ReadOnly` | read-only |
| `ec2:DeleteVpc` | `NoSDNZone` | no sdn_zone configured |
| `ec2:DisassociateAddress` | `ReadOnly` | read-only |
| `ec2:ModifyVolume` | `ReadOnly` | read-only |
| `ec2:RegisterImage` | `ReadOnly` | read-only |
| `ec2:ReleaseAddress` | `ReadOnly` | read-only |
| `ec2:RevokeSecurityGroupIngress` | `ReadOnly` | read-only |

## AWS proxy limits

Requests for an AWS region pass through the AWS proxy, which re-signs them
with SigV4 and the assumed session of the project's AWS account
(`docs/aws-proxy.md`). It refuses these forms with `UnauthorizedOperation`
before any call to AWS:

- SigV4a (`AWS4-ECDSA-P256-SHA256` signatures or an `X-Amz-Region-Set`
  header), so multi-region access points do not work.
- Presigned URLs (query authentication, any `X-Amz-*` query parameter), so
  `aws s3 presign` links are refused.
- `UNSIGNED-PAYLOAD` bodies.

EC2 Query bodies are limited to 1 MiB and other services to 4 MiB.
