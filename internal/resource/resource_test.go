package resource

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestParseRejectsRawShapes(t *testing.T) {
	if _, err := Parse[InstanceID]("nope"); err == nil {
		t.Fatal("expected malformed instance id")
	}
	if _, err := Parse[InstanceID]("i-01234567"); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse[InstanceID]("i-012345678"); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse[InstanceID]("i-0123456"); err == nil {
		t.Fatal("7 hex digits must fail")
	}
	if _, err := Parse[InstanceID]("i-0123456789abcdef01"); err == nil {
		t.Fatal("18 hex digits must fail")
	}
	if _, err := Parse[InstanceID]("i-0123456789ABCDEF0"); err == nil {
		t.Fatal("uppercase hex must fail")
	}
	if _, err := Parse[BucketName]("OK"); err == nil {
		t.Fatal("uppercase bucket must fail")
	}
	if _, err := Parse[BucketName]("logs"); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse[AccountID]("123456789012"); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse[ClientToken]("launch-web-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse[Region](RegionName); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse[Region]("us-east-1"); err == nil {
		t.Fatal("only vws-1 is a region")
	}
}

// TestBucketNameFollowsAWSNamingRules pins the general purpose bucket rules
// that involve periods: dotted names are valid, but a name may not start or
// end with a period, contain two adjacent periods, or match an IP address.
// https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucketnamingrules.html
func TestBucketNameFollowsAWSNamingRules(t *testing.T) {
	valid := []string{
		"logs",
		"build-logs",
		"a.b",
		"example.com",
		"www.example.com",
		"my.example.s3.bucket",
		"a-b.c-d",
		"192.168.0.1.example",
		strings.Repeat("a", 61) + ".b",
	}
	for _, name := range valid {
		if _, err := Parse[BucketName](name); err != nil {
			t.Errorf("%q must be valid: %v", name, err)
		}
	}
	invalid := []string{
		"ab",
		strings.Repeat("a", 64),
		"Edge-Bucket",
		".example.com",
		"example.com.",
		"example..com",
		"192.168.5.4",
		"999.999.999.999",
		"example_com",
		"-example.com",
		"example.com-",
	}
	for _, name := range invalid {
		if _, err := Parse[BucketName](name); err == nil {
			t.Errorf("%q must be invalid", name)
		}
	}
}

func TestJSONDecodesValidatedIDs(t *testing.T) {
	var req RunInstancesRequest
	body := []byte(`{"imageId":"ami-0123456789abcdef0","instanceType":"vws.small","subnetId":"subnet-0123456789abcdef0","count":1}`)
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatal(err)
	}
	if req.ImageID.String() != "ami-0123456789abcdef0" {
		t.Fatalf("image: %s", req.ImageID)
	}
	var bad RunInstancesRequest
	if err := json.Unmarshal([]byte(`{"imageId":"ami-nope","instanceType":"vws.small","subnetId":"subnet-0123456789abcdef0"}`), &bad); err == nil {
		t.Fatal("expected json to reject a bad image id")
	}
}

func TestMintUsesEntropy(t *testing.T) {
	entropy := bytes.NewReader(bytes.Repeat([]byte{0xab}, 32))
	id, err := Mint[InstanceID](entropy)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(id.String(), "i-") || len(id.String()) != 2+17 {
		t.Fatalf("minted %s", id)
	}
	if _, err := Mint[BucketName](entropy); err == nil {
		t.Fatal("bucket names are not minted")
	}
}

func TestOperationIDRoundTrip(t *testing.T) {
	id, err := NewOperationID(ServiceCompute, "5f0c2a9e1b7d4c3a")
	if err != nil {
		t.Fatal(err)
	}
	if id.String() != "op-compute-5f0c2a9e1b7d4c3a" {
		t.Fatal(id)
	}
	parsed, err := Parse[OperationID](id.String())
	if err != nil {
		t.Fatal(err)
	}
	long, err := NewOperationID(ServiceNetwork, "0123456789abcdef0123456789abcdef")
	if err != nil || long.Local() != "0123456789abcdef0123456789abcdef" {
		t.Fatal(err)
	}
	if _, err := Parse[OperationID](long.String()); err != nil {
		t.Fatal(err)
	}
	wide, err := NewOperationID(ServiceStorage, "0123456789abcdef0123")
	if err != nil || wide.String() != "op-storage-0123456789abcdef0123" {
		t.Fatalf("%v %s", err, wide)
	}
	if _, err := Parse[OperationID](wide.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := NewOperationID(ServiceStorage, "0123456789abcde"); err == nil {
		t.Fatal("15 hex digits")
	}
	if _, err := NewOperationID(ServiceStorage, "0123456789abcdef0123456789abcdef0123456789"); err == nil {
		t.Fatal("42 hex digits")
	}
	if parsed != id {
		t.Fatalf("got %#v", parsed)
	}
	if parsed.Service() != ServiceCompute {
		t.Fatal(parsed.Service())
	}
}

func TestVolumeAttachmentIdentityIsTheInstance(t *testing.T) {
	inst, err := Parse[InstanceID]("i-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	vol, err := Parse[VolumeID]("vol-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	owner, err := Parse[AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	item := VolumeAttachment{VolumeID: vol, OwnerID: owner, InstanceID: inst, Status: AttachmentDetaching}
	if item.Identity() != inst.String() || item.Owner() != owner {
		t.Fatalf("identity %s owner %s", item.Identity(), item.Owner())
	}
	if _, err := (DetachVolumeRequest{}).Normalize(); err == nil {
		t.Fatal("missing volume id")
	}
	norm, err := (DetachVolumeRequest{VolumeID: vol, Force: true}).Normalize()
	if err != nil || !norm.Force || norm.Action() != ActionDetachVolume {
		t.Fatalf("normalize: %v %+v", err, norm)
	}
	miss := AttachmentNotFound(vol)
	if !IsAttachmentNotFound(miss) || miss.Field != "attachment" || miss.Kind != KindVolume || miss.Code != CodeNotFound {
		t.Fatalf("%+v", miss)
	}
	if IsAttachmentNotFound(NotFound(KindVolume, vol.String())) {
		t.Fatal("plain volume not-found")
	}
	busy := VolumeAttached(vol)
	if !IsVolumeAttached(busy) || busy.Kind != KindVolume || busy.Code != CodeConflict || busy.ID != vol.String() {
		t.Fatalf("%+v", busy)
	}
	if IsVolumeAttached(VolumeNotAvailable(vol)) || IsVolumeAttached(miss) {
		t.Fatal("other volume errors read as attached")
	}
}

// The EC2 surface sends the model message, so each volume error carries the
// text EC2 sends for its code (#212). The ids are part of the text.
func TestVolumeErrorMessages(t *testing.T) {
	vol, err := Parse[VolumeID]("vol-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	const id = "vol-0123456789abcdef0"
	const idempotent = "Arguments on this idempotent request are inconsistent with arguments used in previous request(s)."
	for _, tc := range []struct {
		name string
		err  *Error
		want string
	}{
		{"not found", NotFound(KindVolume, id), "The volume '" + id + "' does not exist."},
		{"attachment", AttachmentNotFound(vol), "The volume '" + id + "' is not attached to the instance."},
		{"not available", VolumeNotAvailable(vol), id + " is not 'available'."},
		{"not in use", VolumeNotInUse(vol), "Volume '" + id + "' is in the 'available' state."},
		{"root device", VolumeRootDevice(vol), "Volume '" + id + "' is in use as the root device."},
		{"idempotency", IdempotencyMismatch(), idempotent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.err.Message != tc.want {
				t.Fatalf("message %q, want %q", tc.err.Message, tc.want)
			}
		})
	}
}

func TestActionsAreDerived(t *testing.T) {
	got := Actions()
	if len(got) != 26 {
		t.Fatalf("actions: %v", got)
	}
	for _, a := range got {
		if a.String() == "" {
			t.Fatal("blank action")
		}
	}
}

func TestNormalizeRunInstances(t *testing.T) {
	img, _ := Parse[ImageID]("ami-0123456789abcdef0")
	sub, _ := Parse[SubnetID]("subnet-0123456789abcdef0")
	req := RunInstancesRequest{ImageID: img, InstanceType: "t3.micro", SubnetID: sub}
	norm, err := req.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	if norm.Count != 1 {
		t.Fatalf("count %d", norm.Count)
	}
	if norm.Action() != ActionRunInstances {
		t.Fatal(norm.Action())
	}
}

func TestStopTransition(t *testing.T) {
	mid, settled, err := NextInstanceState(ActionStopInstances, InstanceRunning)
	if err != nil {
		t.Fatal(err)
	}
	if mid != InstanceStopping || settled != InstanceStopped {
		t.Fatalf("%s -> %s", mid, settled)
	}
	if _, _, err := NextInstanceState(ActionStopInstances, InstancePending); err == nil {
		t.Fatal("pending cannot stop")
	}
}

func TestRefJSON(t *testing.T) {
	id, _ := Parse[InstanceID]("i-01234567")
	b, err := json.Marshal(id.Ref())
	if err != nil {
		t.Fatal(err)
	}
	var ref Ref
	if err := json.Unmarshal(b, &ref); err != nil {
		t.Fatal(err)
	}
	if ref != id.Ref() {
		t.Fatalf("got %+v", ref)
	}
}

func TestInstanceJSONTags(t *testing.T) {
	owner, _ := Parse[AccountID]("123456789012")
	id, _ := Parse[InstanceID]("i-0123456789abcdef0")
	res, _ := Parse[ReservationID]("r-0123456789abcdef0")
	img, _ := Parse[ImageID]("ami-0123456789abcdef0")
	sub, _ := Parse[SubnetID]("subnet-0123456789abcdef0")
	inst := Instance{
		ID: id, ReservationID: res, OwnerID: owner, State: InstancePending,
		ImageID: img, InstanceType: "vws.small", SubnetID: sub, Zone: ZoneName,
	}
	b, err := json.Marshal(inst)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"instanceId", "reservationId", "ownerId", "imageId", "instanceType", "subnetId", "availabilityZone", "state"} {
		if !bytes.Contains(b, []byte(`"`+key+`"`)) {
			t.Fatalf("missing %s in %s", key, b)
		}
	}
	if bytes.Contains(b, []byte("InstanceId")) {
		t.Fatalf("pascal case leaked: %s", b)
	}
}

func TestOperationJSONOmitsCause(t *testing.T) {
	id, _ := NewOperationID(ServiceCompute, "5f0c2a9e1b7d4c3a")
	op := Operation{
		ID: id, Action: ActionRunInstances, State: OperationRunning,
		CreateTime: time.Unix(0, 0).UTC(), UpdateTime: time.Unix(0, 0).UTC(),
	}
	b, err := json.Marshal(op)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte(`"action":"RunInstances"`)) {
		t.Fatalf("%s", b)
	}
}

func TestCIDRNormalize(t *testing.T) {
	req, err := (CreateSubnetRequest{Cidr: "10.1.0.1/24"}).Normalize()
	if err != nil {
		t.Fatal(err)
	}
	if req.Cidr != "10.1.0.0/24" {
		t.Fatalf("cidr %s", req.Cidr)
	}
	if _, err := (CreateSubnetRequest{Cidr: "nope"}).Normalize(); err == nil {
		t.Fatal("expected bad cidr")
	}
}

func TestIngressProtocolIsCanonical(t *testing.T) {
	id, err := Parse[SecurityGroupID]("sg-01234567")
	if err != nil {
		t.Fatal(err)
	}
	got, err := (AuthorizeSecurityGroupIngressRequest{
		ID:   id,
		Rule: IngressRule{Protocol: "17", FromPort: 53, ToPort: 53, Cidr: "10.0.0.0/16"},
	}).Normalize()
	if err != nil || got.Rule.Protocol != "udp" {
		t.Fatalf("%v %+v", err, got.Rule)
	}
	_, err = (AuthorizeSecurityGroupIngressRequest{
		ID:   id,
		Rule: IngressRule{Protocol: "sctp", FromPort: 1, ToPort: 1, Cidr: "10.0.0.0/16"},
	}).Normalize()
	if CodeOf(err) != CodeInvalidArgument {
		t.Fatalf("sctp: %v", err)
	}
	revoked, err := (RevokeSecurityGroupIngressRequest{
		ID:   id,
		Rule: IngressRule{Protocol: "17", FromPort: 53, ToPort: 53, Cidr: "10.0.0.0/16"},
	}).Normalize()
	if err != nil || revoked.Rule.Protocol != "udp" {
		t.Fatalf("%v %+v", err, revoked.Rule)
	}
}

func TestZeroVpcIDOmitsFromSubnetJSON(t *testing.T) {
	b, err := json.Marshal(CreateSubnetRequest{Cidr: "10.1.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte("vpcId")) {
		t.Fatalf("zero vpc id leaked: %s", b)
	}
}

func TestObjectCapMatchesStorageProto(t *testing.T) {
	if MaxObjectBytes != 4194304 {
		t.Fatalf("MaxObjectBytes = %d, storage proto caps payloads at 4194304", MaxObjectBytes)
	}
	bucket, err := Parse[BucketName]("bkt")
	if err != nil {
		t.Fatal(err)
	}
	key, err := Parse[ObjectKey]("k")
	if err != nil {
		t.Fatal(err)
	}
	req := PutObjectRequest{Bucket: bucket, Key: key, Size: MaxObjectBytes}
	if _, err := req.Normalize(); err != nil {
		t.Fatalf("at cap: %v", err)
	}
	req.Size = MaxObjectBytes + 1
	if _, err := req.Normalize(); CodeOf(err) != CodePayloadTooLarge {
		t.Fatalf("over cap: %v", err)
	}
}

// TestStartRejectedUntilStopped pins the AWS rule: StartInstances only
// applies to a stopped instance. Anything else, including a Stop still in
// flight, is an instance-kind conflict (IncorrectInstanceState on the wire).
func TestStartRejectedUntilStopped(t *testing.T) {
	for _, from := range []InstanceState{InstancePending, InstanceRunning, InstanceStopping, InstanceShuttingDown, InstanceTerminated} {
		_, _, err := NextInstanceState(ActionStartInstances, from)
		var e *Error
		if !errors.As(err, &e) || e.Code != CodeConflict || e.Kind != KindInstance {
			t.Errorf("start from %s: %v", from, err)
		}
	}
}

func TestAssociationIDNamesItsAddress(t *testing.T) {
	id, err := Parse[AddressID]("eipalloc-0db45e5461e9f63e1")
	if err != nil {
		t.Fatal(err)
	}
	assoc := AssociationID(id)
	if assoc != "eipassoc-0db45e5461e9f63e1" {
		t.Fatal(assoc)
	}
	back, err := ParseAssociationID(assoc)
	if err != nil || back != id {
		t.Fatalf("%v %v", back, err)
	}
	for _, bad := range []string{"", "eipalloc-0db45e5461e9f63e1", "eipassoc-x", "eipassoc-"} {
		if _, err := ParseAssociationID(bad); CodeOf(err) != CodeInvalidArgument {
			t.Fatalf("%q: %v", bad, err)
		}
	}
}

func TestKnownImagesIsNotEmpty(t *testing.T) {
	owner, err := Parse[AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	images := KnownImages(owner)
	if len(images) != 1 || images[0].ID.String() != knownImageID || images[0].OwnerID != owner || images[0].Public {
		t.Fatalf("KnownImages = %+v, want one private %s owned by %s", images, knownImageID, owner)
	}
}

func TestEveryListedInstanceTypeLaunches(t *testing.T) {
	for _, it := range InstanceTypes() {
		if got, ok := vwsInstanceType(it.Name); !ok || got != it.Name {
			t.Fatalf("%s is listed but RunInstances maps it to %q, %v", it.Name, got, ok)
		}
	}
}
