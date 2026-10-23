"""End-to-end suite. Drives the EC2 Query and S3 entry points with boto3.

Environment:
  VWS_E2E_BACKEND  fake (default) or grpc. Names the backend behind the entry points.
  VWS_E2E_EC2      EC2 Query endpoint. Default http://127.0.0.1:8081.
  VWS_E2E_S3       S3 endpoint. Default http://127.0.0.1:8082.
  VWS_E2E_IAM      IAM and STS Query endpoint (one listener). Default http://127.0.0.1:8084.
  VWS_E2E_CAPS     Comma list of capabilities the backend has: vm, eip.
                   Default is vm,eip for fake and none for grpc.

  VWS_E2E_WAIT_TIMEOUT  Seconds to poll DescribeInstances for running/stopped
                   between power changes. Default 180.

  VWS_E2E_STRICT   1 makes a skipped step a failure (exit 3). Default is off.

A step that needs a missing capability prints skipped(reason). A skipped step
is not a pass. The run ends with a banner and a status line: PASS, FAIL, or
INCOMPLETE (nothing failed, something was skipped). The exit code is 1 on any
failure, 3 on a skip under VWS_E2E_STRICT, and 0 otherwise.
"""
import base64
import datetime
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request

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

IAM_URL = os.environ.get("VWS_E2E_IAM", "http://127.0.0.1:8084")
EC2_URL = os.environ.get("VWS_E2E_EC2", "http://127.0.0.1:8081")


def client(service, key, secret, token=None, url=IAM_URL):
    return boto3.client(
        service, endpoint_url=url, region_name="vws-1", aws_access_key_id=key,
        aws_secret_access_key=secret, aws_session_token=token,
        config=Config(retries={"total_max_attempts": 1}))


iam = client("iam", KW["aws_access_key_id"], KW["aws_secret_access_key"])
sts = client("sts", KW["aws_access_key_id"], KW["aws_secret_access_key"])

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


WAIT_TIMEOUT = float(os.environ.get("VWS_E2E_WAIT_TIMEOUT", "180"))


def wait_attached(vid, iid, device, timeout=WAIT_TIMEOUT):
    """Polls DescribeVolumes after AttachVolume. The volume must read in-use
    with its attachment on iid at every poll, attaching until the disk is on
    the machine, then attached (#214)."""
    deadline = time.monotonic() + timeout
    while True:
        vol = ec2.describe_volumes(VolumeIds=[vid])["Volumes"][0]
        att = vol.get("Attachments") or []
        check(vol["State"] == "in-use" and len(att) == 1 and att[0]["InstanceId"] == iid and att[0]["Device"] == device
              and att[0]["State"] in ("attaching", "attached"), f"volume after attach {vol}")
        if att[0]["State"] == "attached":
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"{vid} still {att[0]['State']} after {timeout:.0f}s, want attached")
        time.sleep(1)


def wait_state(iid, want, timeout=WAIT_TIMEOUT):
    """Polls DescribeInstances until iid reaches want, like the boto3
    instance_stopped/instance_running waiters. Start or Stop issued before the
    previous transition settles is IncorrectInstanceState on AWS too."""
    deadline = time.monotonic() + timeout
    seen = None
    while True:
        res = ec2.describe_instances(InstanceIds=[iid])["Reservations"]
        seen = res[0]["Instances"][0]["State"]["Name"] if res else None
        if seen == want:
            return seen
        if seen in ("terminated", "shutting-down"):
            raise AssertionError(f"{iid} is {seen}, waiting for {want}")
        if time.monotonic() >= deadline:
            raise AssertionError(f"{iid} still {seen} after {timeout:.0f}s, want {want}")
        time.sleep(2)


def run_instance(token):
    return ec2.run_instances(
        ImageId="ami-0123456789abcdef0", InstanceType="t3.micro", MinCount=1, MaxCount=1,
        SubnetId=S["subnet"], ClientToken=token,
        TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": "e2e-web"}]}],
    )["Instances"][0]["InstanceId"]


def network():
    S["vpc"] = step("CreateVpc", lambda: ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"])
    S["subnet"] = step("CreateSubnet", lambda: ec2.create_subnet(VpcId=S["vpc"], CidrBlock="10.0.1.0/24")["Subnet"]["SubnetId"])
    def subnet_with_zone():
        sid = ec2.create_subnet(VpcId=S["vpc"], CidrBlock="10.0.2.0/24", AvailabilityZone="vws-1a")["Subnet"]["SubnetId"]
        ec2.delete_subnet(SubnetId=sid)
    step("CreateSubnet AvailabilityZone=vws-1a", subnet_with_zone)
    step("DescribeSubnets returns AvailabilityZone and MapPublicIpOnLaunch", lambda: check(
        all(s.get("AvailabilityZone") == "vws-1a" and s.get("MapPublicIpOnLaunch") is False
            for s in ec2.describe_subnets(SubnetIds=[S["subnet"]])["Subnets"]), "subnet fields missing"))
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
    def gp3_volume():
        vid = ec2.create_volume(AvailabilityZone="vws-1a", Size=1, VolumeType="gp3")["VolumeId"]
        got = ec2.describe_volumes(VolumeIds=[vid])["Volumes"][0]["VolumeType"]
        ec2.delete_volume(VolumeId=vid)
        check(got == "gp3", f"type {got}")
    step("CreateVolume VolumeType=gp3 reads back as gp3", gp3_volume)
    step(
        "CreateVolume VolumeType=io3 is UnknownVolumeType",
        lambda: ec2_error(
            "UnknownVolumeType",
            lambda: ec2.create_volume(AvailabilityZone="vws-1a", Size=1, VolumeType="io3"),
        ),
    )
    def modify_volume():
        vid = ec2.create_volume(AvailabilityZone="vws-1a", Size=1)["VolumeId"]
        ec2.get_waiter("volume_available").wait(VolumeIds=[vid], WaiterConfig={"Delay": 1, "MaxAttempts": 30})
        mod = ec2.modify_volume(VolumeId=vid, Size=2)["VolumeModification"]
        check(mod["VolumeId"] == vid and mod["TargetSize"] == 2 and mod["OriginalSize"] == 1, f"modification {mod}")
        deadline = time.monotonic() + 30
        while ec2.describe_volumes(VolumeIds=[vid])["Volumes"][0]["Size"] != 2:
            check(time.monotonic() < deadline, "size did not reach 2")
            time.sleep(1)
        ec2_error("InvalidParameterValue", lambda: ec2.modify_volume(VolumeId=vid, Size=1))
        ec2.delete_volume(VolumeId=vid)
    step("ModifyVolume grows a volume and refuses to shrink it", modify_volume)
    step("DescribeVolumes has CreateTime", lambda: check(
        all("CreateTime" in v for v in ec2.describe_volumes()["Volumes"]), "CreateTime missing"))
    def restore():
        snap = ec2.create_snapshot(VolumeId=S["vol"])["SnapshotId"]
        ec2.get_waiter("snapshot_completed").wait(SnapshotIds=[snap], WaiterConfig={"Delay": 1, "MaxAttempts": 30})
        vol = ec2.create_volume(AvailabilityZone="vws-1a", SnapshotId=snap)
        got = ec2.describe_volumes(VolumeIds=[vol["VolumeId"]])["Volumes"][0]
        ec2.get_waiter("volume_available").wait(VolumeIds=[vol["VolumeId"]], WaiterConfig={"Delay": 1, "MaxAttempts": 30})
        ec2.delete_volume(VolumeId=vol["VolumeId"])
        check(got.get("SnapshotId") == snap and got["Size"] == 10, f"restored {got}")
        S["restored_snap"] = snap
    step("CreateVolume SnapshotId (restore)", restore)
    for name, fn in [
        ("DescribeVpcs", ec2.describe_vpcs), ("DescribeSubnets", ec2.describe_subnets),
        ("DescribeSecurityGroups", ec2.describe_security_groups), ("DescribeKeyPairs", ec2.describe_key_pairs),
        ("DescribeVolumes", ec2.describe_volumes), ("DescribeImages", ec2.describe_images),
    ]:
        step(name, fn)
    step("DescribeVolumes MaxResults=1000 (aws cli default)", lambda: check(
        ec2.describe_volumes(MaxResults=1000)["Volumes"], "no volumes"))


def ec2_error(code, call):
    try:
        call()
    except ec2.exceptions.ClientError as exc:
        got = exc.response["Error"]["Code"]
        check(got == code, f"{got} != {code}")
        return
    raise AssertionError("no error")


def s3_error(code, status, call):
    try:
        call()
    except s3.exceptions.ClientError as exc:
        got = (exc.response["Error"]["Code"], exc.response["ResponseMetadata"]["HTTPStatusCode"])
        check(got == (code, status), f"{got} != {(code, status)}")
        return
    raise AssertionError("no error")


def not_found():
    vol, snap, vpc = "vol-00000000000000000", "snap-00000000000000000", "vpc-00000000000000000"
    for name, code, call in [
        ("DeleteVolume", "InvalidVolume.NotFound", lambda: ec2.delete_volume(VolumeId=vol)),
        ("CreateSnapshot", "InvalidVolume.NotFound", lambda: ec2.create_snapshot(VolumeId=vol)),
        ("DeleteSnapshot", "InvalidSnapshot.NotFound", lambda: ec2.delete_snapshot(SnapshotId=snap)),
        ("DeleteVpc", "InvalidVpcID.NotFound", lambda: ec2.delete_vpc(VpcId=vpc)),
        ("DeleteSubnet", "InvalidSubnetID.NotFound", lambda: ec2.delete_subnet(SubnetId="subnet-00000000000000000")),
        ("StopInstances", "InvalidInstanceID.NotFound", lambda: ec2.stop_instances(InstanceIds=["i-00000000000000000"])),
        ("ReleaseAddress", "InvalidAllocationID.NotFound", lambda: ec2.release_address(AllocationId="eipalloc-00000000000000000")),
        ("AssociateAddress", "InvalidAllocationID.NotFound", lambda: ec2.associate_address(
            AllocationId="eipalloc-00000000000000000", InstanceId="i-00000000000000000")),
        ("DisassociateAddress", "InvalidAssociationID.NotFound", lambda: ec2.disassociate_address(
            AssociationId="eipassoc-00000000000000000")),
        ("DetachVolume", "InvalidVolume.NotFound", lambda: ec2.detach_volume(VolumeId=vol)),
    ]:
        step(f"{name} missing is {code}", lambda code=code, call=call: ec2_error(code, call))



# A 2048-bit RSA public key, as RFC 4716 and as base64 DER, and the MD5 of
# its DER SubjectPublicKeyInfo (openssl rsa -pubout -outform DER | openssl md5 -c).
PARITY_RFC4716 = ("---- BEGIN SSH2 PUBLIC KEY ----\nComment: \"e2e\"\n"
                  "AAAAB3NzaC1yc2EAAAADAQABAAABAQClx+r6bOncI1UxjkWluLJh9YURn5VSLugTDfOBvM\n6d1EjqWNRFSkQrLnf6EBSQJM0/+pEPXUtKyLynaeaK/T7RDuyurcZmo0ovWib/CTQz08Bm\nlOs6brqv0TD/3eQmK2o6cSpVKXWKKalyFJwfK3t3i8ZZCuPw6+VWTVoNq+L71oIP/hJgF9\nQJb3F863V+3yoly4RN3dXPADcBJVp/qPmA3AXuolprWOj7eYAAvaxqyiKUt/Htt4L55Gey\n+5fR4fjnH/E2VA1FZotnqG6Bf6nfqfnxJ2IV6hZr6pfQV3psbbzt/tMjhOYBBgAr0R120I\nNm4MIQI8eY9Zgog8QWTIQN\n---- END SSH2 PUBLIC KEY ----\n")
PARITY_DER_B64 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApcfq+mzp3CNVMY5FpbiyYfWFEZ+VUi7oEw3zgbzOndRI6ljURUpEKy53+hAUkCTNP/qRD11LSsi8p2nmiv0+0Q7srq3GZqNKL1om/wk0M9PAZpTrOm66r9Ew/93kJitqOnEqVSl1iimpchScHyt7d4vGWQrj8OvlVk1aDavi+9aCD/4SYBfUCW9xfOt1ft8qJcuETd3VzwA3ASVaf6j5gNwF7qJaa1jo+3mAAL2sasoilLfx7beC+eRnsvuX0eH45x/xNlQNRWaLZ6hugX+p36n58SdiFeoWa+qX0Fd6bG287f7TI4TmAQYAK9EddtCDZuDCECPHmPWYKIPEFkyEDQIDAQAB"
PARITY_RSA_MD5 = "65:e4:c2:b4:21:3e:6e:f2:8b:87:1d:83:2d:fb:e5:e3"


def ppk_mac_ok(text):
    """Checks the HMAC-SHA1 of an unencrypted PuTTY-User-Key-File-2."""
    import hmac
    import struct
    lines = text.rstrip("\n").split("\n")
    head = dict(line.split(": ", 1) for line in lines if ": " in line)
    pub_n = int(head["Public-Lines"])
    i = lines.index(f"Public-Lines: {pub_n}")
    pub = base64.b64decode("".join(lines[i + 1:i + 1 + pub_n]))
    priv_n = int(head["Private-Lines"])
    j = lines.index(f"Private-Lines: {priv_n}")
    priv = base64.b64decode("".join(lines[j + 1:j + 1 + priv_n]))
    def s(b):
        return struct.pack(">I", len(b)) + b
    data = (s(head["PuTTY-User-Key-File-2"].encode()) + s(b"none") + s(head["Comment"].encode())
            + s(pub) + s(priv))
    key = hashlib.sha1(b"putty-private-key-file-mac-key").digest()
    return hmac.new(key, data, hashlib.sha1).hexdigest() == head["Private-MAC"]


def key_parity():
    """#128 follow-ups: EC2 fingerprints, RFC 4716 and DER imports, ppk, MissingParameter."""
    ed_line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG417cXtz5jVkH8Cu0D4exQ0iqZ8aXluTLeM0PhuoDH1"
    ed_fp = base64.b64encode(hashlib.sha256(base64.b64decode(ed_line.split()[1])).digest()).decode()
    step("ImportKeyPair ed25519 fingerprint is base64 SHA-256", lambda: check(
        ec2.describe_key_pairs(KeyNames=["e2e-import"])["KeyPairs"][0]["KeyFingerprint"] == ed_fp, "ed25519 fingerprint"))

    def imported(name, material):
        got = ec2.import_key_pair(KeyName=name, PublicKeyMaterial=material)["KeyFingerprint"]
        check(got == PARITY_RSA_MD5, f"{name} fingerprint {got}")
        listed = ec2.describe_key_pairs(KeyNames=[name])["KeyPairs"][0]
        check(listed["KeyFingerprint"] == PARITY_RSA_MD5 and listed.get("KeyType") == "rsa", f"{name} described {listed}")
    step("ImportKeyPair RFC 4716 RSA, fingerprint MD5 of DER", lambda: imported("e2e-rfc4716", PARITY_RFC4716.encode()))
    step("ImportKeyPair DER RSA, fingerprint MD5 of DER", lambda: imported("e2e-der", base64.b64decode(PARITY_DER_B64)))

    def created_rsa():
        made = ec2.create_key_pair(KeyName="e2e-rsa-fp")["KeyFingerprint"]
        check(len(made) == 59 and made.count(":") == 19, f"created rsa fingerprint {made}")
        listed = ec2.describe_key_pairs(KeyNames=["e2e-rsa-fp"])["KeyPairs"][0]["KeyFingerprint"]
        check(listed == made, f"described {listed} created {made}")
    step("CreateKeyPair rsa fingerprint is colon SHA-1, same on describe", created_rsa)

    def ppk():
        mat = ec2.create_key_pair(KeyName="e2e-ppk", KeyType="ed25519", KeyFormat="ppk")["KeyMaterial"]
        check(mat.startswith("PuTTY-User-Key-File-2: ssh-ed25519\n") and ppk_mac_ok(mat), f"ppk {mat[:60]!r}")
    step("CreateKeyPair KeyFormat=ppk is a PuTTY key with a valid MAC", ppk)
    step("ImportKeyPair ecdsa is InvalidKey.Format", lambda: ec2_error("InvalidKey.Format", lambda: ec2.import_key_pair(
        KeyName="e2e-ecdsa", PublicKeyMaterial=b"ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEm0")))
    loose = boto3.client(
        "ec2", endpoint_url=EC2_URL,
        config=Config(retries={"total_max_attempts": 1}, parameter_validation=False), **KW)
    step("ImportKeyPair without PublicKeyMaterial is MissingParameter", lambda: ec2_error(
        "MissingParameter", lambda: loose.import_key_pair(KeyName="e2e-nokey")))

def key_launch():
    """#128: key formats, ImportKeyPair, and a launch with KeyName and UserData."""
    def made(key_type, header):
        mat = ec2.create_key_pair(KeyName=f"e2e-{key_type}", KeyType=key_type)["KeyMaterial"]
        check(mat.startswith(header), f"{key_type} material starts {mat[:40]!r}")
    step("CreateKeyPair KeyType=rsa is PKCS#1 PEM", lambda: made("rsa", "-----BEGIN RSA PRIVATE KEY-----"))
    step("CreateKeyPair KeyType=ed25519 is OpenSSH", lambda: made("ed25519", "-----BEGIN OPENSSH PRIVATE KEY-----"))
    pub = b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG417cXtz5jVkH8Cu0D4exQ0iqZ8aXluTLeM0PhuoDH1 e2e@vws\n"
    step("ImportKeyPair", lambda: check(
        ec2.import_key_pair(KeyName="e2e-import", PublicKeyMaterial=pub)["KeyName"] == "e2e-import", "import"))
    step("ImportKeyPair malformed key is InvalidKey.Format", lambda: ec2_error("InvalidKey.Format", lambda: ec2.import_key_pair(
        KeyName="e2e-bad", PublicKeyMaterial=b"not a key")))
    step("DescribeKeyPairs KeyType of an imported key", lambda: check(
        ec2.describe_key_pairs(KeyNames=["e2e-import"])["KeyPairs"][0].get("KeyType") == "ed25519", "key type"))
    key_parity()
    user_data = "#cloud-config\nruncmd:\n  - echo vws > /tmp/vws-user-data\n"

    def launch():
        return ec2.run_instances(
            ImageId="ami-0123456789abcdef0", InstanceType="t3.micro", MinCount=1, MaxCount=1,
            SubnetId=S["subnet"], ClientToken="tok-key", KeyName="e2e-import", UserData=user_data,
        )["Instances"][0]
    inst = step("RunInstances KeyName and UserData", launch, "vm")
    if inst:
        iid = inst["InstanceId"]
        step("RunInstances returns KeyName", lambda: check(inst.get("KeyName") == "e2e-import", f"{inst.get('KeyName')}"), "vm")
        step("DescribeInstances returns KeyName", lambda: check(
            ec2.describe_instances(InstanceIds=[iid])["Reservations"][0]["Instances"][0].get("KeyName") == "e2e-import", "keyName"), "vm")
        step("DescribeInstanceAttribute userData", lambda: check(base64.b64decode(
            ec2.describe_instance_attribute(InstanceId=iid, Attribute="userData")["UserData"]["Value"]).decode() == user_data, "userData"), "vm")
        step("RunInstances unknown KeyName is InvalidKeyPair.NotFound", lambda: ec2_error("InvalidKeyPair.NotFound", lambda: ec2.run_instances(
            ImageId="ami-0123456789abcdef0", InstanceType="t3.micro", MinCount=1, MaxCount=1,
            SubnetId=S["subnet"], ClientToken="tok-nokey", KeyName="e2e-missing")), "vm")
        step("TerminateInstances keyed instance", lambda: ec2.terminate_instances(InstanceIds=[iid]), "vm")

    def delete_key(name):
        deadline = time.monotonic() + WAIT_TIMEOUT
        while True:
            try:
                return ec2.delete_key_pair(KeyName=name)
            except Exception:  # noqa: BLE001 - compute keeps the key while a terminating instance names it
                if time.monotonic() >= deadline:
                    raise
                time.sleep(2)
    for name in ("e2e-rsa", "e2e-ed25519", "e2e-import"):
        step(f"DeleteKeyPair {name}", lambda name=name: delete_key(name))


def refused_launch():
    """#197: a refused launch leaves no volume, and DescribeVolumes stays up."""
    before = {v["VolumeId"] for v in ec2.describe_volumes()["Volumes"]}
    ec2_error("InvalidAMIID.NotFound", lambda: ec2.run_instances(
        ImageId="ami-fedcba9876543210", InstanceType="t3.micro", MinCount=1, MaxCount=1,
        SubnetId=S["subnet"], ClientToken="tok-other-region"))
    after = {v["VolumeId"] for v in ec2.describe_volumes()["Volumes"]}
    check(after == before, f"refused launch added volumes {sorted(after - before)}")


def vms():
    step("RunInstances other-region AMI is InvalidAMIID.NotFound and leaves no volume", refused_launch, "vm")
    S["iid"] = step("RunInstances", lambda: run_instance("tok-1"), "vm")

    def same_instance():
        check(run_instance("tok-1") == S["iid"], "instance id changed")
    if S["iid"]:
        step("RunInstances same token", same_instance, "vm")
        step("DescribeInstances", lambda: check(ec2.describe_instances()["Reservations"], "no reservation"), "vm")

        def described_tags():
            res = ec2.describe_instances(InstanceIds=[S["iid"]])["Reservations"][0]
            tags = {t["Key"]: t["Value"] for t in res["Instances"][0].get("Tags", [])}
            check(tags.get("Name") == "e2e-web" and res.get("OwnerId"), f"reservation {res}")
        step("DescribeInstances returns the Name tag and OwnerId", described_tags, "vm")

        def described_placement():
            inst = ec2.describe_instances(InstanceIds=[S["iid"]])["Reservations"][0]["Instances"][0]
            check(inst.get("VpcId") == S["vpc"] and inst.get("LaunchTime"), f"instance {inst}")
        step("DescribeInstances returns VpcId and LaunchTime", described_placement, "vm")
        def root_device():
            inst = ec2.describe_instances(InstanceIds=[S["iid"]])["Reservations"][0]["Instances"][0]
            maps = inst.get("BlockDeviceMappings") or []
            check(inst.get("RootDeviceName") == "/dev/xvda" and inst.get("RootDeviceType") == "ebs", f"root {inst.get('RootDeviceName')}")
            check(len(maps) == 1 and maps[0]["DeviceName"] == "/dev/xvda" and maps[0]["Ebs"]["DeleteOnTermination"] is True, f"mappings {maps}")
            check(isinstance(maps[0]["Ebs"].get("AttachTime"), datetime.datetime), f"mapping AttachTime {maps}")
            vol = ec2.describe_volumes(VolumeIds=[maps[0]["Ebs"]["VolumeId"]])["Volumes"][0]
            att = vol.get("Attachments") or []
            check(att and isinstance(att[0].get("AttachTime"), datetime.datetime), f"attachment AttachTime {att}")
            check(att and att[0]["InstanceId"] == S["iid"] and att[0]["Device"] == "/dev/xvda" and att[0]["DeleteOnTermination"] is True, f"volume {vol}")
            check(any(v["VolumeId"] == vol["VolumeId"] for v in ec2.describe_volumes()["Volumes"]), "root volume not listed")
        step("DescribeInstances RootDeviceName/BlockDeviceMappings and DescribeVolumes root volume", root_device, "vm")
        tagged()
        step("wait for running after RunInstances", lambda: wait_state(S["iid"], "running"), "vm")
        step("DescribeInstances instance-state-name with two values", lambda: check(any(
            i["InstanceId"] == S["iid"] for r in ec2.describe_instances(Filters=[
                {"Name": "instance-state-name", "Values": ["stopped", "running"]}])["Reservations"]
            for i in r["Instances"]), "running instance missing"), "vm")
        step("StopInstances without ClientToken", lambda: check(
            ec2.stop_instances(InstanceIds=[S["iid"]])["StoppingInstances"], "empty"), "vm")
        step("wait for stopped", lambda: wait_state(S["iid"], "stopped"), "vm")
        def detach_data_volume():
            vid = ec2.create_volume(AvailabilityZone="vws-1a", Size=1)["VolumeId"]
            ec2.get_waiter("volume_available").wait(VolumeIds=[vid], WaiterConfig={"Delay": 1, "MaxAttempts": 30})
            att = ec2.attach_volume(VolumeId=vid, InstanceId=S["iid"], Device="/dev/sdf")
            # EC2 answers attaching; the volume is in-use from then on (#214).
            check(att["VolumeId"] == vid and att["InstanceId"] == S["iid"] and att["State"] == "attaching", f"attach {att}")
            wait_attached(vid, S["iid"], "/dev/sdf")
            det = ec2.detach_volume(VolumeId=vid, InstanceId=S["iid"], Device="/dev/sdf")
            check(det["VolumeId"] == vid and det["InstanceId"] == S["iid"] and det["Device"] == "/dev/sdf" and det["State"] == "detaching", f"detach {det}")
            check(isinstance(det.get("AttachTime"), datetime.datetime), f"attach time {det}")
            ec2.delete_volume(VolumeId=vid)
        step("DetachVolume then DeleteVolume", detach_data_volume, "vm")
        step("StartInstances", lambda: ec2.start_instances(InstanceIds=[S["iid"]]), "vm")
        step("wait for running", lambda: wait_state(S["iid"], "running"), "vm")
        associate()
        step("TerminateInstances", lambda: ec2.terminate_instances(InstanceIds=[S["iid"]]), "vm")
    else:
        step("RunInstances follow-ups", lambda: None, "vm")


ODD_TAGS = {
    "Name": "e2e tagged", "Owner Team": "Platform / SRE: a=b, c+d @x", "vws-looks-internal": "v",
    "K" * 128: "max key", "long": "v" * 256, "유니코드": "값" * 85, "empty": "", "env": "dev",
}


def network_tags():
    """VPC and subnet tags round-trip through create, CreateTags, EC2 and the console API."""
    def spec(kind):
        return [{"ResourceType": kind, "Tags": [{"Key": k, "Value": v} for k, v in ODD_TAGS.items()]}]

    def tags_of(item):
        return {t["Key"]: t["Value"] for t in item.get("Tags", [])}
    vpc = step("CreateVpc TagSpecifications", lambda: ec2.create_vpc(
        CidrBlock="10.9.0.0/16", TagSpecifications=spec("vpc"))["Vpc"]["VpcId"])
    sub = step("CreateSubnet TagSpecifications", lambda: ec2.create_subnet(
        VpcId=vpc, CidrBlock="10.9.1.0/24", TagSpecifications=spec("subnet"))["Subnet"]["SubnetId"])
    vpc_tags = lambda: tags_of(ec2.describe_vpcs(VpcIds=[vpc])["Vpcs"][0])
    sub_tags = lambda: tags_of(ec2.describe_subnets(SubnetIds=[sub])["Subnets"][0])
    step("DescribeVpcs returns the tags exactly", lambda: check(vpc_tags() == ODD_TAGS, f"{vpc_tags()}"))
    step("DescribeSubnets returns the tags exactly", lambda: check(sub_tags() == ODD_TAGS, f"{sub_tags()}"))
    want = dict(ODD_TAGS, Name="renamed", added="yes")
    step("CreateTags on a VPC and a subnet in one call", lambda: ec2.create_tags(
        Resources=[vpc, sub], Tags=[{"Key": "Name", "Value": "renamed"}, {"Key": "added", "Value": "yes"}]))
    step("CreateTags merged VPC tags", lambda: check(vpc_tags() == want, f"{vpc_tags()}"))
    step("CreateTags merged subnet tags", lambda: check(sub_tags() == want, f"{sub_tags()}"))
    step("console GET /api/v1/vpcs/{id} returns the tags", lambda: check(
        console_get(f"/api/v1/vpcs/{vpc}").get("tags") == want, "console vpc tags"))
    step("console GET /api/v1/subnets returns the tags", lambda: check(any(
        s.get("subnetId") == sub and s.get("tags") == want
        for s in console_get("/api/v1/subnets?pageSize=100")["items"]), "console subnet tags"))


def console_get(path):
    req = urllib.request.Request(
        os.environ.get("VWS_E2E_CONSOLE", "http://127.0.0.1:8080") + path,
        headers={"Authorization": "Bearer " + os.environ.get("VWS_E2E_CONSOLE_TOKEN", "dev-token")})
    with urllib.request.urlopen(req, timeout=10) as res:
        return json.load(res)


def tagged():
    """Any valid AWS tag round-trips exactly, including through a stop that rewrites labels."""
    iid = step("RunInstances with tags labels cannot hold", lambda: ec2.run_instances(
        ImageId="ami-0123456789abcdef0", InstanceType="t3.micro", MinCount=1, MaxCount=1,
        SubnetId=S["subnet"], ClientToken="tok-tags",
        TagSpecifications=[{"ResourceType": "instance", "Tags": [
            {"Key": k, "Value": v} for k, v in ODD_TAGS.items()]}])["Instances"][0]["InstanceId"], "vm")
    if not iid:
        return

    def ec2_tags():
        got = ec2.describe_instances(InstanceIds=[iid])["Reservations"][0]["Instances"][0].get("Tags", [])
        return {t["Key"]: t["Value"] for t in got}
    step("DescribeInstances returns the tags exactly", lambda: check(ec2_tags() == ODD_TAGS, f"{ec2_tags()}"), "vm")
    step("console GET /api/v1/instances returns the tags exactly", lambda: check(
        console_get("/api/v1/instances/" + iid)["tags"] == ODD_TAGS, "tags differ"), "vm")
    step("wait for running (tagged)", lambda: wait_state(iid, "running"), "vm")
    step("StopInstances (tagged)", lambda: ec2.stop_instances(InstanceIds=[iid]), "vm")
    step("wait for stopped (tagged)", lambda: wait_state(iid, "stopped"), "vm")
    step("tags survive StopInstances", lambda: check(ec2_tags() == ODD_TAGS, f"{ec2_tags()}"), "vm")
    def create_tags():
        ec2.create_tags(Resources=[iid], Tags=[{"Key": "Name", "Value": "renamed"}, {"Key": "Cost Center", "Value": "42"}])
        want = dict(ODD_TAGS, Name="renamed", **{"Cost Center": "42"})
        check(ec2_tags() == want, f"{ec2_tags()}")
        check(console_get("/api/v1/instances/" + iid)["tags"] == want, "console tags differ")
    step("CreateTags renames and adds tags, keeping the rest", create_tags, "vm")
    step("TerminateInstances (tagged)", lambda: ec2.terminate_instances(InstanceIds=[iid]), "vm")


def associate():
    need = "eip" if "vm" in CAPS else "vm"
    alloc = step("AllocateAddress for AssociateAddress", lambda: ec2.allocate_address(Domain="vpc")["AllocationId"], need)
    if not alloc:
        step("AssociateAddress follow-ups", lambda: None, need)
        return
    S["assoc"] = step("AssociateAddress", lambda: ec2.associate_address(
        AllocationId=alloc, InstanceId=S["iid"])["AssociationId"], need)

    def described():
        got = ec2.describe_addresses(AllocationIds=[alloc])["Addresses"][0]
        check(got.get("InstanceId") == S["iid"] and got.get("AssociationId") == S["assoc"], f"address {got}")
    step("DescribeAddresses shows the association", described, need)

    def instance_public_ip():
        ip = ec2.describe_addresses(AllocationIds=[alloc])["Addresses"][0]["PublicIp"]
        inst = ec2.describe_instances(InstanceIds=[S["iid"]])["Reservations"][0]["Instances"][0]
        nic = (inst.get("NetworkInterfaces") or [{}])[0]
        check(inst.get("PublicIpAddress") == ip and nic.get("Association", {}).get("PublicIp") == ip, f"instance {inst}")
        check(console_get(f"/api/v1/instances/{S['iid']}").get("publicIpAddress") == ip, "console publicIpAddress")
    step("DescribeInstances and the console show the elastic IP", instance_public_ip, need)
    step("DisassociateAddress", lambda: ec2.disassociate_address(AssociationId=S["assoc"]), need)
    step("DescribeAddresses after DisassociateAddress", lambda: check(
        "InstanceId" not in ec2.describe_addresses(AllocationIds=[alloc])["Addresses"][0], "still associated"), need)
    step("DescribeInstances has no public IP after DisassociateAddress", lambda: check(
        "PublicIpAddress" not in ec2.describe_instances(InstanceIds=[S["iid"]])["Reservations"][0]["Instances"][0],
        "public ip kept"), need)
    step("DisassociateAddress again is InvalidAssociationID.NotFound", lambda: ec2_error(
        "InvalidAssociationID.NotFound", lambda: ec2.disassociate_address(AssociationId=S["assoc"])), need)
    step("ReleaseAddress after DisassociateAddress", lambda: ec2.release_address(AllocationId=alloc), need)


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
    # VWS's region is not us-east-1, so an owned name is 409 (#315).
    step("S3 CreateBucket again is BucketAlreadyOwnedByYou", lambda: s3_error(
        "BucketAlreadyOwnedByYou", 409, lambda: s3.create_bucket(Bucket=b)))
    for key, body in [("a/k", b"hello"), ("a/j", b"x"), ("top", b"y")]:
        step(f"S3 PutObject {key}", lambda key=key, body=body: s3.put_object(Bucket=b, Key=key, Body=body))

    def get(key, want):
        got = s3.get_object(Bucket=b, Key=key)["Body"].read()
        check(got == want, f"body {got!r} != {want!r}")
    step("S3 GetObject returns the bytes", lambda: get("a/k", b"hello"))
    step("S3 HeadObject", lambda: check(s3.head_object(Bucket=b, Key="a/k")["ContentLength"] == 5, "length"))
    step("S3 Overwrite", lambda: s3.put_object(Bucket=b, Key="a/k", Body=b"world!"))
    step("S3 GetObject after overwrite", lambda: get("a/k", b"world!"))

    def checksum_mode(op, call):
        # Raw header instead of ChecksumMode=, and the raw response header
        # instead of ChecksumSHA256, so older botocore releases work too.
        def add(request, **_):
            # Newer botocore already sets it on GetObject; headers append.
            del request.headers["x-amz-checksum-mode"]
            request.headers["x-amz-checksum-mode"] = "ENABLED"
        event = f"before-sign.s3.{op}"
        s3.meta.events.register_first(event, add)
        try:
            got = call(Bucket=b, Key="a/k")["ResponseMetadata"]["HTTPHeaders"]
        finally:
            s3.meta.events.unregister(event, add)
        want = "cR6WCTOekrA93AohGCfbpCHzj57YudgG4f/djBX/oD0="  # base64(sha256(b"world!"))
        check(got.get("x-amz-checksum-sha256") == want, f"x-amz-checksum-sha256 {got.get('x-amz-checksum-sha256')!r} != {want!r}")
    step("S3 HeadObject x-amz-checksum-mode ENABLED returns SHA-256", lambda: checksum_mode("HeadObject", s3.head_object))
    step("S3 GetObject x-amz-checksum-mode ENABLED returns SHA-256", lambda: checksum_mode("GetObject", s3.get_object))

    def missing(code, status, call):
        try:
            call()
        except s3.exceptions.ClientError as exc:
            err = exc.response
            got = (err["Error"]["Code"], err["ResponseMetadata"]["HTTPStatusCode"])
            check(got == (code, status), f"{got} != {(code, status)}")
            return
        raise AssertionError("no error")
    step("S3 GetObject missing key is NoSuchKey", lambda: missing(
        "NoSuchKey", 404, lambda: s3.get_object(Bucket=b, Key="no/such")))
    # HEAD has no body, so botocore reports the status as the code.
    step("S3 HeadObject missing key is 404", lambda: missing(
        "404", 404, lambda: s3.head_object(Bucket=b, Key="no/such")))
    step("S3 GetObject missing bucket is NoSuchBucket", lambda: missing(
        "NoSuchBucket", 404, lambda: s3.get_object(Bucket="no-such-bucket", Key="a/k")))
    step("S3 DeleteObject missing key succeeds", lambda: s3.delete_object(Bucket=b, Key="no/such"))
    step("S3 ListObjectsV2 prefix", lambda: check(
        [o["Key"] for o in s3.list_objects_v2(Bucket=b, Prefix="a/")["Contents"]] == ["a/j", "a/k"], "keys"))
    step("S3 ListObjectsV2 delimiter", lambda: check(
        [p["Prefix"] for p in s3.list_objects_v2(Bucket=b, Delimiter="/")["CommonPrefixes"]] == ["a/"], "prefixes"))
    step("S3 ListObjects prefix", lambda: check(
        [o["Key"] for o in s3.list_objects(Bucket=b, Prefix="a/")["Contents"]] == ["a/j", "a/k"], "keys"))
    step("S3 ListObjects delimiter", lambda: check(
        [p["Prefix"] for p in s3.list_objects(Bucket=b, Delimiter="/")["CommonPrefixes"]] == ["a/"], "prefixes"))

    def v1_pages():
        pages = s3.get_paginator("list_objects").paginate(Bucket=b, PaginationConfig={"PageSize": 1})
        keys = [o["Key"] for page in pages for o in page.get("Contents", [])]
        check(keys == sorted(keys) and len(keys) == len(set(keys)) >= 3, f"keys {keys}")
    step("S3 ListObjects marker pages", v1_pages)
    def put_once(body):
        # Set the header on the wire instead of passing IfNoneMatch=, which
        # only botocore releases from late 2024 accept. Signed like any header.
        def add(request, **_):
            request.headers["If-None-Match"] = "*"
        s3.meta.events.register_first("before-sign.s3.PutObject", add)
        try:
            return s3.put_object(Bucket=b, Key="once", Body=body)
        finally:
            s3.meta.events.unregister("before-sign.s3.PutObject", add)
    step("S3 PutObject If-None-Match * new key", lambda: put_once(b"1"))
    for body in (b"1", b"2"):
        step(f"S3 PutObject If-None-Match * existing key ({body!r}) is 412", lambda body=body: missing(
            "PreconditionFailed", 412, lambda: put_once(body)))
    step("S3 GetObject after refused put", lambda: get("once", b"1"))

    def put_sha256(key, body, checksum):
        # Raw header, like put_once: ChecksumSHA256= needs a botocore that
        # knows flexible checksums, and newer ones also add their own CRC32.
        def add(request, **_):
            request.headers["x-amz-checksum-sha256"] = checksum
        s3.meta.events.register_first("before-sign.s3.PutObject", add)
        try:
            return s3.put_object(Bucket=b, Key=key, Body=body)
        finally:
            s3.meta.events.unregister("before-sign.s3.PutObject", add)
    hello_sha256 = base64.b64encode(hashlib.sha256(b"hello").digest()).decode()
    empty_sha256 = base64.b64encode(hashlib.sha256(b"").digest()).decode()
    step("S3 PutObject wrong x-amz-checksum-sha256 is BadDigest", lambda: missing(
        "BadDigest", 400, lambda: put_sha256("bad", b"hello", empty_sha256)))
    step("S3 GetObject after BadDigest is NoSuchKey", lambda: missing(
        "NoSuchKey", 404, lambda: s3.get_object(Bucket=b, Key="bad")))
    step("S3 PutObject matching x-amz-checksum-sha256", lambda: put_sha256("sha", b"hello", hello_sha256))
    step("S3 DeleteObject sha", lambda: s3.delete_object(Bucket=b, Key="sha"))
    step("S3 DeleteObject once", lambda: s3.delete_object(Bucket=b, Key="once"))
    step("S3 DeleteObject", lambda: s3.delete_object(Bucket=b, Key="top"))
    for key in ("a/k", "a/j"):
        step(f"S3 DeleteObject {key}", lambda key=key: s3.delete_object(Bucket=b, Key=key))
    step("S3 DeleteBucket", lambda: s3.delete_bucket(Bucket=b))


def aws_error(code, call):
    try:
        call()
    except Exception as exc:  # noqa: BLE001
        got = getattr(exc, "response", {}).get("Error", {}).get("Code")
        check(got == code, f"error {got}, want {code}: {exc}")
        return
    raise AssertionError(f"no error, want {code}")


def identity():
    """IAM users, groups, policies, keys and roles, then STS AssumeRole, with
    the new keys used against EC2 to show Authorize is applied."""
    me = step("STS GetCallerIdentity (root key)", lambda: sts.get_caller_identity())
    if not me:
        return
    account = me["Account"]
    step("STS GetCallerIdentity is the account root", lambda: check(me["Arn"] == f"arn:vws:iam::{account}:root", me["Arn"]))
    describe = json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["ec2:Describe*", "sts:AssumeRole"], "Resource": "*"}]})
    step("IAM CreateUser", lambda: check(
        iam.create_user(UserName="e2e-bob", Path="/e2e/")["User"]["Arn"] == f"arn:vws:iam::{account}:user/e2e/e2e-bob", "user arn"))
    step("IAM CreateUser again is EntityAlreadyExists", lambda: aws_error(
        "EntityAlreadyExists", lambda: iam.create_user(UserName="e2e-bob")))
    step("IAM GetUser", lambda: check(iam.get_user(UserName="e2e-bob")["User"]["Path"] == "/e2e/", "path"))
    step("IAM ListUsers PathPrefix", lambda: check(
        [u["UserName"] for u in iam.list_users(PathPrefix="/e2e/")["Users"]] == ["e2e-bob"], "list"))
    step("IAM GetUser missing is NoSuchEntity", lambda: aws_error("NoSuchEntity", lambda: iam.get_user(UserName="nobody")))
    # #314: paging, UpdateUser and DeleteUser on a user of its own.
    step("IAM CreateUser e2e-dave", lambda: iam.create_user(UserName="e2e-dave", Path="/e2e/"))
    first = step("IAM ListUsers MaxItems 1 is truncated", lambda: iam.list_users(PathPrefix="/e2e/", MaxItems=1))
    step("IAM ListUsers first page", lambda: check(
        [u["UserName"] for u in first["Users"]] == ["e2e-bob"] and first["IsTruncated"] and first["Marker"], first))
    step("IAM ListUsers Marker returns the next page", lambda: check(
        [u["UserName"] for u in iam.list_users(PathPrefix="/e2e/", Marker=first["Marker"])["Users"]] == ["e2e-dave"],
        "page 2"))
    # botocore refuses MaxItems 0 itself; send it unvalidated to reach the server.
    loose_iam = boto3.client(
        "iam", endpoint_url=IAM_URL,
        config=Config(retries={"total_max_attempts": 1}, parameter_validation=False), **KW)
    step("IAM ListUsers MaxItems 0 is ValidationError", lambda: aws_error(
        "ValidationError", lambda: loose_iam.list_users(MaxItems=0)))
    step("IAM UpdateUser NewPath", lambda: iam.update_user(UserName="e2e-dave", NewPath="/e2e/moved/"))
    step("IAM GetUser after UpdateUser", lambda: check(
        iam.get_user(UserName="e2e-dave")["User"]["Arn"] == f"arn:vws:iam::{account}:user/e2e/moved/e2e-dave", "arn"))
    step("IAM UpdateUser missing is NoSuchEntity", lambda: aws_error(
        "NoSuchEntity", lambda: iam.update_user(UserName="nobody", NewPath="/")))
    step("IAM DeleteUser e2e-dave", lambda: iam.delete_user(UserName="e2e-dave"))
    step("IAM DeleteUser again is NoSuchEntity", lambda: aws_error(
        "NoSuchEntity", lambda: iam.delete_user(UserName="e2e-dave")))
    S["policy_arn"] = step("IAM CreatePolicy", lambda: iam.create_policy(
        PolicyName="e2e-describe", PolicyDocument=describe)["Policy"]["Arn"])
    step("IAM CreatePolicy malformed is MalformedPolicyDocument", lambda: aws_error(
        "MalformedPolicyDocument", lambda: iam.create_policy(PolicyName="bad", PolicyDocument="{not json")))
    step("IAM GetPolicyVersion returns the document", lambda: check(
        iam.get_policy_version(PolicyArn=S["policy_arn"], VersionId="v1")["PolicyVersion"]["Document"]["Statement"][0]["Effect"] == "Allow",
        "document"))
    step("IAM SetDefaultPolicyVersion", lambda: iam.set_default_policy_version(
        PolicyArn=S["policy_arn"], VersionId="v1"))
    step("IAM SetDefaultPolicyVersion missing version is NoSuchEntity", lambda: aws_error(
        "NoSuchEntity", lambda: iam.set_default_policy_version(PolicyArn=S["policy_arn"], VersionId="v2")))
    step("IAM DeletePolicyVersion default is DeleteConflict", lambda: aws_error(
        "DeleteConflict", lambda: iam.delete_policy_version(PolicyArn=S["policy_arn"], VersionId="v1")))
    step("IAM DeletePolicyVersion unknown version is NoSuchEntity", lambda: aws_error(
        "NoSuchEntity", lambda: iam.delete_policy_version(PolicyArn=S["policy_arn"], VersionId="v2")))
    step("IAM DeletePolicyVersion malformed version is InvalidInput", lambda: aws_error(
        "InvalidInput", lambda: iam.delete_policy_version(PolicyArn=S["policy_arn"], VersionId="1")))
    step("IAM CreatePolicyVersion", lambda: check(
        iam.create_policy_version(PolicyArn=S["policy_arn"], PolicyDocument=describe,
                                  SetAsDefault=True)["PolicyVersion"]["VersionId"] == "v2",
        "version"))
    step("IAM ListPolicyVersions has v1 and v2", lambda: check(
        sorted(v["VersionId"] for v in iam.list_policy_versions(PolicyArn=S["policy_arn"])["Versions"]) == ["v1", "v2"],
        "versions"))
    step("IAM GetPolicyVersion v2 returns its document", lambda: check(
        iam.get_policy_version(PolicyArn=S["policy_arn"], VersionId="v2")["PolicyVersion"]["Document"]["Statement"][0]["Effect"] == "Allow",
        "document"))
    step("IAM DeletePolicyVersion non-default v1", lambda: iam.delete_policy_version(
        PolicyArn=S["policy_arn"], VersionId="v1"))
    step("IAM CreateGroup", lambda: iam.create_group(GroupName="e2e-readers"))
    step("IAM CreateGroup again is EntityAlreadyExists", lambda: aws_error(
        "EntityAlreadyExists", lambda: iam.create_group(GroupName="e2e-readers")))
    step("IAM UpdateGroup NewPath", lambda: iam.update_group(GroupName="e2e-readers", NewPath="/e2e/"))
    step("IAM ListGroups PathPrefix", lambda: check(
        [g["GroupName"] for g in iam.list_groups(PathPrefix="/e2e/")["Groups"]] == ["e2e-readers"], "groups"))
    step("IAM AttachGroupPolicy", lambda: iam.attach_group_policy(GroupName="e2e-readers", PolicyArn=S["policy_arn"]))
    step("IAM AddUserToGroup", lambda: iam.add_user_to_group(GroupName="e2e-readers", UserName="e2e-bob"))
    step("IAM GetGroup lists the member", lambda: check(
        [u["UserName"] for u in iam.get_group(GroupName="e2e-readers")["Users"]] == ["e2e-bob"], "members"))
    step("IAM ListGroupsForUser", lambda: check(
        [g["GroupName"] for g in iam.list_groups_for_user(UserName="e2e-bob")["Groups"]] == ["e2e-readers"], "groups"))
    step("IAM PutUserPolicy (inline deny)", lambda: iam.put_user_policy(
        UserName="e2e-bob", PolicyName="no-volumes", PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Deny", "Action": "ec2:DescribeVolumes", "Resource": "*"}]})))
    step("IAM ListUserPolicies", lambda: check(iam.list_user_policies(UserName="e2e-bob")["PolicyNames"] == ["no-volumes"], "inline"))
    step("IAM GetUserPolicy returns the document", lambda: check(
        iam.get_user_policy(UserName="e2e-bob", PolicyName="no-volumes")["PolicyDocument"]["Statement"][0]["Effect"] == "Deny", "document"))
    key = step("IAM CreateAccessKey", lambda: iam.create_access_key(UserName="e2e-bob")["AccessKey"])
    if not key:
        return
    step("IAM ListAccessKeys", lambda: check(
        [k["AccessKeyId"] for k in iam.list_access_keys(UserName="e2e-bob")["AccessKeyMetadata"]] == [key["AccessKeyId"]], "keys"))
    # #314 bundle 2: the AWS key shape, the 2 keys per user quota, paging
    # and the NoSuchEntity and ValidationError answers.
    step("IAM CreateAccessKey is Active with a 40 character secret", lambda: check(
        key["Status"] == "Active" and len(key["SecretAccessKey"]) == 40 and key["UserName"] == "e2e-bob", key["Status"]))
    key2 = step("IAM CreateAccessKey a second key", lambda: iam.create_access_key(UserName="e2e-bob")["AccessKey"])
    step("IAM CreateAccessKey a third key is LimitExceeded", lambda: aws_error(
        "LimitExceeded", lambda: iam.create_access_key(UserName="e2e-bob")))
    if key2:
        ids = sorted([key["AccessKeyId"], key2["AccessKeyId"]])
        page = step("IAM ListAccessKeys MaxItems 1 is truncated", lambda: iam.list_access_keys(UserName="e2e-bob", MaxItems=1))
        step("IAM ListAccessKeys first page", lambda: check(
            page["IsTruncated"] and page.get("Marker") and
            [k["AccessKeyId"] for k in page["AccessKeyMetadata"]] == ids[:1], page))
        step("IAM ListAccessKeys next page", lambda: check(
            [k["AccessKeyId"] for k in iam.list_access_keys(
                UserName="e2e-bob", MaxItems=1, Marker=page["Marker"])["AccessKeyMetadata"]] == ids[1:], "page 2") if page else None)
        step("IAM DeleteAccessKey the second key", lambda: iam.delete_access_key(
            UserName="e2e-bob", AccessKeyId=key2["AccessKeyId"]))
        step("IAM DeleteAccessKey again is NoSuchEntity", lambda: aws_error(
            "NoSuchEntity", lambda: iam.delete_access_key(UserName="e2e-bob", AccessKeyId=key2["AccessKeyId"])))
    step("IAM ListAccessKeys for a missing user is NoSuchEntity", lambda: aws_error(
        "NoSuchEntity", lambda: iam.list_access_keys(UserName="nobody")))
    step("IAM DeleteAccessKey with a malformed id is ValidationError", lambda: aws_error(
        "ValidationError", lambda: iam.delete_access_key(UserName="e2e-bob", AccessKeyId="not-a-key-id-00000")))
    step("IAM ListAccessKeys holds the first key only", lambda: check(
        [k["AccessKeyId"] for k in iam.list_access_keys(UserName="e2e-bob")["AccessKeyMetadata"]] == [key["AccessKeyId"]], "keys"))
    bob_ec2 = client("ec2", key["AccessKeyId"], key["SecretAccessKey"], url=EC2_URL)
    bob_iam = client("iam", key["AccessKeyId"], key["SecretAccessKey"])
    bob_sts = client("sts", key["AccessKeyId"], key["SecretAccessKey"])
    step("new user key: allowed EC2 DescribeVpcs", lambda: bob_ec2.describe_vpcs())
    step("new user key: EC2 CreateVpc is UnauthorizedOperation", lambda: aws_error(
        "UnauthorizedOperation", lambda: bob_ec2.create_vpc(CidrBlock="10.42.0.0/16")))
    step("new user key: inline Deny beats the group Allow", lambda: aws_error(
        "UnauthorizedOperation", lambda: bob_ec2.describe_volumes()))
    step("new user key: IAM ListUsers is AccessDenied", lambda: aws_error("AccessDenied", lambda: bob_iam.list_users()))
    step("new user key: STS GetCallerIdentity needs no policy", lambda: check(
        bob_sts.get_caller_identity()["Arn"] == f"arn:vws:iam::{account}:user/e2e/e2e-bob", "bob arn"))
    step("IAM GetAccessKeyLastUsed names the key owner", lambda: check(
        iam.get_access_key_last_used(AccessKeyId=key["AccessKeyId"])["UserName"] == "e2e-bob", "owner"))
    step("GetCallerIdentity with a wrong secret is SignatureDoesNotMatch", lambda: aws_error(
        "SignatureDoesNotMatch", lambda: client("sts", key["AccessKeyId"], "wrong-secret").get_caller_identity()))
    step("unknown key is InvalidClientTokenId", lambda: aws_error(
        "InvalidClientTokenId", lambda: client("sts", "AKIANOSUCHKEY0000000", "x").get_caller_identity()))
    trust = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole",
                        "Principal": {"AWS": f"arn:vws:iam::{account}:user/e2e/e2e-bob"}}]})
    S["role_arn"] = step("IAM CreateRole", lambda: iam.create_role(
        RoleName="e2e-ops", AssumeRolePolicyDocument=trust)["Role"]["Arn"])
    step("IAM GetRole returns the trust policy", lambda: check(
        iam.get_role(RoleName="e2e-ops")["Role"]["AssumeRolePolicyDocument"]["Statement"][0]["Action"] == "sts:AssumeRole", "trust"))
    step("IAM PutRolePolicy", lambda: iam.put_role_policy(RoleName="e2e-ops", PolicyName="vpcs", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["ec2:CreateVpc", "ec2:DeleteVpc"], "Resource": "*"}]})))
    creds = step("STS AssumeRole", lambda: bob_sts.assume_role(
        RoleArn=S["role_arn"], RoleSessionName="e2e", DurationSeconds=900)["Credentials"])
    if creds:
        role_ec2 = client("ec2", creds["AccessKeyId"], creds["SecretAccessKey"], creds["SessionToken"], url=EC2_URL)
        role_sts = client("sts", creds["AccessKeyId"], creds["SecretAccessKey"], creds["SessionToken"])
        step("assumed role: STS GetCallerIdentity", lambda: check(
            role_sts.get_caller_identity()["Arn"] == f"arn:vws:sts::{account}:assumed-role/e2e-ops/e2e", "role arn"))

        def role_vpc():
            vpc = role_ec2.create_vpc(CidrBlock="10.42.0.0/16")["Vpc"]["VpcId"]
            role_ec2.delete_vpc(VpcId=vpc)
        step("assumed role: EC2 CreateVpc and DeleteVpc", role_vpc)
        step("assumed role without the session token is rejected", lambda: aws_error(
            "AuthFailure", lambda: client("ec2", creds["AccessKeyId"], creds["SecretAccessKey"], url=EC2_URL).describe_vpcs()))
    step("STS AssumeRole by a principal the trust policy does not name is AccessDenied", lambda: aws_error(
        "AccessDenied", lambda: client("sts", creds["AccessKeyId"], creds["SecretAccessKey"], creds["SessionToken"]).assume_role(
            RoleArn=S["role_arn"], RoleSessionName="again")) if creds else None)
    step("IAM DeleteUser with keys is DeleteConflict", lambda: aws_error(
        "DeleteConflict", lambda: iam.delete_user(UserName="e2e-bob")))
    step("IAM DeleteRolePolicy", lambda: iam.delete_role_policy(RoleName="e2e-ops", PolicyName="vpcs"))
    step("IAM DeleteRole", lambda: iam.delete_role(RoleName="e2e-ops"))
    step("IAM DeleteAccessKey", lambda: iam.delete_access_key(UserName="e2e-bob", AccessKeyId=key["AccessKeyId"]))
    step("deleted key is InvalidClientTokenId", lambda: aws_error("InvalidClientTokenId", lambda: bob_sts.get_caller_identity()))
    step("IAM DeleteUserPolicy", lambda: iam.delete_user_policy(UserName="e2e-bob", PolicyName="no-volumes"))
    step("IAM RemoveUserFromGroup", lambda: iam.remove_user_from_group(GroupName="e2e-readers", UserName="e2e-bob"))
    step("IAM DeletePolicy while attached is DeleteConflict", lambda: aws_error(
        "DeleteConflict", lambda: iam.delete_policy(PolicyArn=S["policy_arn"])))
    step("IAM DetachGroupPolicy", lambda: iam.detach_group_policy(GroupName="e2e-readers", PolicyArn=S["policy_arn"]))
    step("IAM DeletePolicy", lambda: iam.delete_policy(PolicyArn=S["policy_arn"]))
    step("IAM DeleteGroup", lambda: iam.delete_group(GroupName="e2e-readers"))
    step("IAM DeleteUser", lambda: iam.delete_user(UserName="e2e-bob"))


CONSOLE_URL = os.environ.get("VWS_E2E_CONSOLE", "http://127.0.0.1:8080")


def console_call(method, path, body=None, cookies=None, headers=None):
    """One console request. Returns (status, json body or None, Set-Cookie headers)."""
    h = {}
    data = None
    if method not in ("GET", "HEAD"):
        # A browser sends its Origin; the console only takes JSON writes.
        h["Origin"] = CONSOLE_URL
        h["Content-Type"] = "application/json"
        data = json.dumps(body if body is not None else {}).encode()
    h.update(headers or {})
    if cookies:
        h["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
    req = urllib.request.Request(CONSOLE_URL + path, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=10) as res:
            raw = res.read()
            return res.status, (json.loads(raw) if raw else None), res.headers.get_all("Set-Cookie") or []
    except urllib.error.HTTPError as e:
        raw = e.read()
        return e.code, (json.loads(raw) if raw else None), e.headers.get_all("Set-Cookie") or []


def console_login():
    """Console sign-in with an IAM user's password: an HttpOnly session cookie,
    CSRF on writes, the user's policies on every request, and logout."""
    me = sts.get_caller_identity()
    account = me["Account"]
    if not step("IAM CreateUser e2e-carol", lambda: iam.create_user(UserName="e2e-carol")):
        return
    step("IAM CreateLoginProfile", lambda: iam.create_login_profile(UserName="e2e-carol", Password="e2e carol pass 1"))
    step("IAM CreateLoginProfile weak password is PasswordPolicyViolation", lambda: aws_error(
        "PasswordPolicyViolation", lambda: iam.update_login_profile(UserName="e2e-carol", Password="short")))
    step("IAM GetLoginProfile", lambda: check(
        iam.get_login_profile(UserName="e2e-carol")["LoginProfile"]["UserName"] == "e2e-carol", "profile"))

    def expect(want, got):
        check(got[0] == want, f"status {got[0]} {got[1]}")
        return got
    creds = {"account": account, "userName": "e2e-carol", "password": "e2e carol pass 1"}
    step("console login wrong password is 401", lambda: expect(401, console_call(
        "POST", "/api/v1/auth/login", dict(creds, password="nope nope nope"))))
    step("console login unknown user is the same 401", lambda: expect(401, console_call(
        "POST", "/api/v1/auth/login", dict(creds, userName="e2e-nobody"))))
    step("console login from a foreign Origin is 403", lambda: expect(403, console_call(
        "POST", "/api/v1/auth/login", creds, headers={"Origin": "https://evil.example"})))
    step("console login as a form is 415", lambda: expect(415, console_call(
        "POST", "/api/v1/auth/login", creds, headers={"Content-Type": "application/x-www-form-urlencoded"})))
    got = step("console login", lambda: expect(200, console_call("POST", "/api/v1/auth/login", creds)))
    if not got:
        return
    _, body, set_cookies = got
    jar = {}
    for raw in set_cookies:
        name, _, rest = raw.partition("=")
        jar[name] = rest.split(";", 1)[0]
    session_cookie = next((c for c in set_cookies if c.startswith("vws_session=")), "")
    step("session cookie is HttpOnly, Secure, SameSite=Strict", lambda: check(
        all(a in session_cookie for a in ("HttpOnly", "Secure", "SameSite=Strict")), session_cookie))
    step("login body names the user and hides the token", lambda: check(
        body["principal"] == f"arn:vws:iam::{account}:user/e2e-carol" and jar["vws_session"] not in json.dumps(body), body))
    step("GET /api/v1/auth/session", lambda: check(expect(200, console_call(
        "GET", "/api/v1/auth/session", cookies=jar))[1]["principal"].endswith(":user/e2e-carol"), "principal"))
    step("session says loginEnabled true with IAM", lambda: check(console_call(
        "GET", "/api/v1/auth/session", cookies=jar)[1]["loginEnabled"] is True, "loginEnabled"))
    step("signed-out session is 401 with IAM", lambda: expect(401, console_call("GET", "/api/v1/auth/session")))
    step("no policy: GET /api/v1/vpcs is 403", lambda: expect(403, console_call("GET", "/api/v1/vpcs", cookies=jar)))
    step("IAM PutUserPolicy ec2:Describe*", lambda: iam.put_user_policy(
        UserName="e2e-carol", PolicyName="read", PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "ec2:Describe*", "Resource": "*"}]})))
    step("with the policy: GET /api/v1/vpcs is 200", lambda: expect(200, console_call("GET", "/api/v1/vpcs", cookies=jar)))
    write = {"Idempotency-Key": "e2e-login-vpc-1"}
    step("POST without the CSRF header is 403", lambda: expect(403, console_call(
        "POST", "/api/v1/vpcs", {"cidrBlock": "10.43.0.0/16"}, cookies=jar, headers=write)))
    step("POST with CSRF but no ec2:CreateVpc is 403", lambda: expect(403, console_call(
        "POST", "/api/v1/vpcs", {"cidrBlock": "10.43.0.0/16"}, cookies=jar, headers=dict(write, **{"X-CSRF-Token": jar["vws_csrf"]}))))
    step("cookie write from a foreign Origin is 403", lambda: expect(403, console_call(
        "POST", "/api/v1/vpcs", {"cidrBlock": "10.43.0.0/16"}, cookies=jar,
        headers=dict(write, **{"X-CSRF-Token": jar["vws_csrf"], "Origin": "https://evil.example"}))))
    step("console logout", lambda: expect(204, console_call(
        "POST", "/api/v1/auth/logout", cookies=jar, headers={"X-CSRF-Token": jar["vws_csrf"]})))
    step("after logout the session is 401", lambda: expect(401, console_call("GET", "/api/v1/vpcs", cookies=jar)))
    step("bearer console token still works", lambda: console_get("/api/v1/vpcs"))
    step("IAM DeleteUser with a login profile is DeleteConflict", lambda: aws_error(
        "DeleteConflict", lambda: iam.delete_user(UserName="e2e-carol")))
    step("IAM DeleteUserPolicy (carol)", lambda: iam.delete_user_policy(UserName="e2e-carol", PolicyName="read"))
    step("IAM DeleteLoginProfile", lambda: iam.delete_login_profile(UserName="e2e-carol"))
    step("IAM DeleteUser e2e-carol", lambda: iam.delete_user(UserName="e2e-carol"))


STATIC_CONSOLE_URL = os.environ.get("VWS_E2E_STATIC_CONSOLE", "")


def expect_status(want, got):
    check(got[0] == want, f"status {got[0]} {got[1]}")
    return got


def console_static():
    """A second process on -iam static (the default install): sign-in is off,
    the session route says so without credentials, and the bearer token works.
    Runs only when VWS_E2E_STATIC_CONSOLE names that process's console."""
    if not STATIC_CONSOLE_URL:
        return
    global CONSOLE_URL
    saved, CONSOLE_URL = CONSOLE_URL, STATIC_CONSOLE_URL
    try:
        step("static: anonymous session is exactly {loginEnabled:false}", lambda: check(
            expect_status(200, console_call("GET", "/api/v1/auth/session"))[1] == {"loginEnabled": False}, "body"))
        step("static: bearer session is root with loginEnabled false", lambda: check(
            (lambda b: b["loginEnabled"] is False and b["root"] is True)(expect_status(200, console_call(
                "GET", "/api/v1/auth/session", headers={"Authorization": "Bearer " + os.environ.get("VWS_E2E_CONSOLE_TOKEN", "dev-token")}))[1]), "body"))
        for path in ("/api/v1/auth/login", "/api/v1/auth/logout"):
            step(f"static: POST {path} is 501 Unimplemented", lambda path=path: check(
                expect_status(501, console_call("POST", path, {"account": "123456789012", "userName": "root", "password": "x" * 12}))[1]["error"]["code"]
                == "Unimplemented", "code"))
        step("static: bearer GET /api/v1/vpcs is 200", lambda: expect_status(200, console_call(
            "GET", "/api/v1/vpcs", headers={"Authorization": "Bearer " + os.environ.get("VWS_E2E_CONSOLE_TOKEN", "dev-token")})))
    finally:
        CONSOLE_URL = saved


def cleanup():
    if S.get("restored_snap"):
        step("DeleteSnapshot", lambda: ec2.delete_snapshot(SnapshotId=S["restored_snap"]))
    step("DeleteVolume", lambda: ec2.delete_volume(VolumeId=S["vol"]))
    step("DeleteKeyPair", lambda: ec2.delete_key_pair(KeyName="k1"))
    step("DeleteSecurityGroup", lambda: ec2.delete_security_group(GroupId=S["sg"]))
    step("DeleteSubnet", lambda: ec2.delete_subnet(SubnetId=S["subnet"]))
    step("DeleteVpc", lambda: ec2.delete_vpc(VpcId=S["vpc"]))


if __name__ == "__main__":
    print(f"backend={BACKEND} caps={sorted(CAPS) or 'none'}")
    network()
    network_tags()
    not_found()
    vms()
    key_launch()
    addresses()
    objects()
    identity()
    console_login()
    console_static()
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
