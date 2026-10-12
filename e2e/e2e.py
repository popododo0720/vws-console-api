"""End-to-end suite. Drives the EC2 Query and S3 entry points with boto3.

Environment:
  VWS_E2E_BACKEND  fake (default) or grpc. Names the backend behind the entry points.
  VWS_E2E_EC2      EC2 Query endpoint. Default http://127.0.0.1:8081.
  VWS_E2E_S3       S3 endpoint. Default http://127.0.0.1:8082.
  VWS_E2E_CAPS     Comma list of capabilities the backend has: vm, eip.
                   Default is vm,eip for fake and none for grpc.

  VWS_E2E_STRICT   1 makes a skipped step a failure (exit 3). Default is off.

A step that needs a missing capability prints skipped(reason). A skipped step
is not a pass. The run ends with a banner and a status line: PASS, FAIL, or
INCOMPLETE (nothing failed, something was skipped). The exit code is 1 on any
failure, 3 on a skip under VWS_E2E_STRICT, and 0 otherwise.
"""
import os
import sys

import boto3
from botocore.config import Config

BACKEND = os.environ.get("VWS_E2E_BACKEND", "fake")
CAPS = set(filter(None, os.environ.get("VWS_E2E_CAPS", "vm,eip" if BACKEND == "fake" else "").split(",")))
KW = dict(aws_access_key_id="AKIDEXAMPLE", aws_secret_access_key="secret", region_name="vws-1")
ec2 = boto3.client(
    "ec2", endpoint_url=os.environ.get("VWS_E2E_EC2", "http://127.0.0.1:8081"),
    config=Config(retries={"total_max_attempts": 1}), **KW)
s3 = boto3.client(
    "s3", endpoint_url=os.environ.get("VWS_E2E_S3", "http://127.0.0.1:8082"),
    config=Config(retries={"total_max_attempts": 1}, s3={"addressing_style": "path"}), **KW)

STRICT = os.environ.get("VWS_E2E_STRICT") == "1"
results = {"ok": 0, "skipped": 0, "FAIL": 0}
SKIPPED = []
S = {}


def step(name, fn, need=None):
    if need and need not in CAPS:
        results["skipped"] += 1
        SKIPPED.append(name)
        print(f"skipped({need} not available on {BACKEND} backend)  {name}")
        return None
    try:
        out = fn()
    except Exception as exc:  # noqa: BLE001
        results["FAIL"] += 1
        print(f"FAIL  {name}: {str(exc)[:300]}")
        return None
    results["ok"] += 1
    print(f"ok    {name}")
    return out


def check(cond, msg):
    if not cond:
        raise AssertionError(msg)


def run_instance(token):
    return ec2.run_instances(
        ImageId="ami-0123456789abcdef0", InstanceType="t3.micro", MinCount=1, MaxCount=1,
        SubnetId=S["subnet"], ClientToken=token)["Instances"][0]["InstanceId"]


def network():
    S["vpc"] = step("CreateVpc", lambda: ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"])
    S["subnet"] = step("CreateSubnet", lambda: ec2.create_subnet(VpcId=S["vpc"], CidrBlock="10.0.1.0/24")["Subnet"]["SubnetId"])
    S["sg"] = step("CreateSecurityGroup", lambda: ec2.create_security_group(GroupName="web", Description="d", VpcId=S["vpc"])["GroupId"])
    step("CreateKeyPair", lambda: ec2.create_key_pair(KeyName="k1"))
    S["vol"] = step("CreateVolume", lambda: ec2.create_volume(AvailabilityZone="vws-1a", Size=10, ClientToken="v0")["VolumeId"])

    def same_volume():
        check(ec2.create_volume(AvailabilityZone="vws-1a", Size=10, ClientToken="v0")["VolumeId"] == S["vol"], "volume id changed")
    step("CreateVolume same token", same_volume)
    def standard_volume():
        vid = ec2.create_volume(AvailabilityZone="vws-1a", Size=1, VolumeType="standard")["VolumeId"]
        got = ec2.describe_volumes(VolumeIds=[vid])["Volumes"][0]["VolumeType"]
        ec2.delete_volume(VolumeId=vid)
        check(got == "standard", f"type {got}")
    step("CreateVolume VolumeType=standard", standard_volume)
    for name, fn in [
        ("DescribeVpcs", ec2.describe_vpcs), ("DescribeSubnets", ec2.describe_subnets),
        ("DescribeSecurityGroups", ec2.describe_security_groups), ("DescribeKeyPairs", ec2.describe_key_pairs),
        ("DescribeVolumes", ec2.describe_volumes), ("DescribeImages", ec2.describe_images),
    ]:
        step(name, fn)
    step("DescribeVolumes MaxResults=1000 (aws cli default)", lambda: check(
        ec2.describe_volumes(MaxResults=1000)["Volumes"], "no volumes"))


def vms():
    S["iid"] = step("RunInstances", lambda: run_instance("tok-1"), "vm")

    def same_instance():
        check(run_instance("tok-1") == S["iid"], "instance id changed")
    if S["iid"]:
        step("RunInstances same token", same_instance, "vm")
        step("DescribeInstances", lambda: check(ec2.describe_instances()["Reservations"], "no reservation"), "vm")
        step("StopInstances without ClientToken", lambda: check(
            ec2.stop_instances(InstanceIds=[S["iid"]])["StoppingInstances"], "empty"), "vm")
        step("StartInstances", lambda: ec2.start_instances(InstanceIds=[S["iid"]]), "vm")
        step("TerminateInstances", lambda: ec2.terminate_instances(InstanceIds=[S["iid"]]), "vm")
    else:
        step("RunInstances follow-ups", lambda: None, "vm")


def addresses():
    S["alloc"] = step("AllocateAddress Domain=vpc", lambda: ec2.allocate_address(Domain="vpc")["AllocationId"], "eip")
    if S["alloc"]:
        step("DescribeAddresses", lambda: check(
            any(a["AllocationId"] == S["alloc"] for a in ec2.describe_addresses()["Addresses"]), "not listed"), "eip")
        step("ReleaseAddress", lambda: ec2.release_address(AllocationId=S["alloc"]), "eip")
    else:
        step("AllocateAddress follow-ups", lambda: None, "eip")


def objects():
    b = "bucket-one"
    step("S3 CreateBucket", lambda: s3.create_bucket(Bucket=b))
    step("S3 HeadBucket", lambda: s3.head_bucket(Bucket=b))
    for key, body in [("a/k", b"hello"), ("a/j", b"x"), ("top", b"y")]:
        step(f"S3 PutObject {key}", lambda key=key, body=body: s3.put_object(Bucket=b, Key=key, Body=body))

    def get(key, want):
        got = s3.get_object(Bucket=b, Key=key)["Body"].read()
        check(got == want, f"body {got!r} != {want!r}")
    step("S3 GetObject returns the bytes", lambda: get("a/k", b"hello"))
    step("S3 HeadObject", lambda: check(s3.head_object(Bucket=b, Key="a/k")["ContentLength"] == 5, "length"))
    step("S3 Overwrite", lambda: s3.put_object(Bucket=b, Key="a/k", Body=b"world!"))
    step("S3 GetObject after overwrite", lambda: get("a/k", b"world!"))
    step("S3 ListObjectsV2 prefix", lambda: check(
        [o["Key"] for o in s3.list_objects_v2(Bucket=b, Prefix="a/")["Contents"]] == ["a/j", "a/k"], "keys"))
    step("S3 ListObjectsV2 delimiter", lambda: check(
        [p["Prefix"] for p in s3.list_objects_v2(Bucket=b, Delimiter="/")["CommonPrefixes"]] == ["a/"], "prefixes"))
    step("S3 DeleteObject", lambda: s3.delete_object(Bucket=b, Key="top"))
    for key in ("a/k", "a/j"):
        step(f"S3 DeleteObject {key}", lambda key=key: s3.delete_object(Bucket=b, Key=key))
    step("S3 DeleteBucket", lambda: s3.delete_bucket(Bucket=b))


def cleanup():
    step("DeleteVolume", lambda: ec2.delete_volume(VolumeId=S["vol"]))
    step("DeleteKeyPair", lambda: ec2.delete_key_pair(KeyName="k1"))
    step("DeleteSecurityGroup", lambda: ec2.delete_security_group(GroupId=S["sg"]))
    step("DeleteSubnet", lambda: ec2.delete_subnet(SubnetId=S["subnet"]))
    step("DeleteVpc", lambda: ec2.delete_vpc(VpcId=S["vpc"]))


if __name__ == "__main__":
    print(f"backend={BACKEND} caps={sorted(CAPS) or 'none'}")
    network()
    vms()
    addresses()
    objects()
    cleanup()
    print(f"ok={results['ok']} skipped={results['skipped']} FAIL={results['FAIL']}")
    if SKIPPED:
        bar = "!" * 60
        print(f"\n{bar}\n{len(SKIPPED)} STEP(S) SKIPPED ON THE {BACKEND.upper()} BACKEND. NOT TESTED:")
        for name in SKIPPED:
            print(f"  - {name}")
        print(f"{bar}")
    status = "FAIL" if results["FAIL"] else "INCOMPLETE" if SKIPPED else "PASS"
    print(f"status={status}")
    if results["FAIL"]:
        sys.exit(1)
    sys.exit(3 if SKIPPED and STRICT else 0)
