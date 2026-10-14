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

func TestActionsAreDerived(t *testing.T) {
	got := Actions()
	if len(got) != 24 {
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
	if len(images) != 1 || images[0].ID.String() != knownImageID || images[0].OwnerID != owner {
		t.Fatalf("KnownImages = %+v, want one %s owned by %s", images, knownImageID, owner)
	}
}

func TestEveryListedInstanceTypeLaunches(t *testing.T) {
	for _, it := range InstanceTypes() {
		if got, ok := vwsInstanceType(it.Name); !ok || got != it.Name {
			t.Fatalf("%s is listed but RunInstances maps it to %q, %v", it.Name, got, ok)
		}
	}
}
