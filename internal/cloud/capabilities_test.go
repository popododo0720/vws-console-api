package cloud

import (
	"context"
	"errors"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

type stubCapabilities struct {
	doc resource.RegionCapabilities
	err error
}

func (s stubCapabilities) RegionCapabilities(context.Context, string) (resource.RegionCapabilities, error) {
	return s.doc, s.err
}

func TestDerivedReadRequiresExplicitEmptyCapability(t *testing.T) {
	for _, state := range []resource.ActionState{
		0, resource.ActionEmpty, resource.ActionSupported, resource.ActionPartial, resource.ActionUnsupported,
	} {
		svc := New(Config{Capabilities: stubCapabilities{doc: resource.RegionCapabilities{
			Actions: map[string]resource.ActionCapability{"ec2:DescribeRouteTables": {State: state}},
		}}})
		empty, err := svc.ReadIsEmpty(t.Context(), "DescribeRouteTables")
		if err != nil || empty != (state == resource.ActionEmpty) {
			t.Fatalf("state=%s empty=%v error=%v", state, empty, err)
		}
	}
	failure := errors.New("capabilities unavailable")
	svc := New(Config{Capabilities: stubCapabilities{err: failure}})
	if _, err := svc.ReadIsEmpty(t.Context(), "DescribeRouteTables"); !errors.Is(err, failure) {
		t.Fatalf("capability failure was lost: %v", err)
	}
}

// countingNetwork counts the address calls that reach the backend.
type countingNetwork struct {
	backend.Network
	allocates, describes int
}

func (n *countingNetwork) AllocateAddress(
	ctx context.Context, m backend.Mutation, req resource.AllocateAddressRequest,
) (resource.Accepted[resource.Address], error) {
	n.allocates++
	return n.Network.AllocateAddress(ctx, m, req)
}

func (n *countingNetwork) DescribeAddresses(
	ctx context.Context, s backend.Scope, q resource.AddressQuery,
) (resource.Page[resource.Address], error) {
	n.describes++
	return n.Network.DescribeAddresses(ctx, s, q)
}

func gatedService(t *testing.T, caps backend.Capabilities) (*Service, *countingNetwork, resource.Caller) {
	t.Helper()
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	set := fake.New(fake.Options{}).Set()
	network := &countingNetwork{Network: set.Network}
	set.Network = network
	return New(Config{Backends: set, Capabilities: caps}), network, resource.Caller{Account: account, Subject: "t"}
}

func addressDoc(allocate, describe resource.ActionCapability) resource.RegionCapabilities {
	return resource.RegionCapabilities{
		Region: resource.RegionName, Kind: resource.RegionKindProxmox,
		Actions: map[string]resource.ActionCapability{
			resource.ActionAllocateAddress.CapabilityKey(): allocate,
			resource.ReadDescribeAddresses.CapabilityKey(): describe,
		},
	}
}

func TestUnsupportedMutationIsRefusedBeforeTheBackend(t *testing.T) {
	doc := addressDoc(
		resource.ActionCapability{State: resource.ActionUnsupported, ReasonCode: "NoElasticIP", Reason: "no Elastic IP"},
		resource.ActionCapability{State: resource.ActionEmpty})
	for _, tc := range []struct {
		name string
		doc  resource.RegionCapabilities
	}{
		{"unsupported", doc},
		{"missing from the document", resource.RegionCapabilities{
			Region: resource.RegionName, Kind: resource.RegionKindProxmox,
		}},
		{"empty, which no valid document holds", addressDoc(
			resource.ActionCapability{State: resource.ActionEmpty}, resource.ActionCapability{State: resource.ActionEmpty})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A restarted process keeps nothing, and a retry with the same
			// client token is refused the same way.
			for range 2 {
				svc, network, c := gatedService(t, stubCapabilities{doc: tc.doc})
				for range 2 {
					_, err := svc.AllocateAddress(t.Context(), c, token(t, "caps-1"), resource.AllocateAddressRequest{})
					if e := resource.AsError(err); !resource.IsUnsupported(e) {
						t.Fatalf("AllocateAddress error = %v, want UnsupportedOperation", err)
					}
				}
				if network.allocates != 0 {
					t.Errorf("backend saw %d allocates", network.allocates)
				}
			}
		})
	}
}

func TestEmptyReadAnswersAnEmptyPageWithoutTheBackend(t *testing.T) {
	for _, tc := range []struct {
		name string
		doc  resource.RegionCapabilities
	}{
		{"empty", addressDoc(
			resource.ActionCapability{State: resource.ActionSupported}, resource.ActionCapability{State: resource.ActionEmpty})},
		{"missing from the document", resource.RegionCapabilities{
			Region: resource.RegionName, Kind: resource.RegionKindProxmox,
			Actions: map[string]resource.ActionCapability{
				resource.ActionAllocateAddress.CapabilityKey(): {State: resource.ActionSupported},
			},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, network, c := gatedService(t, stubCapabilities{doc: tc.doc})
			if _, err := svc.AllocateAddress(t.Context(), c, token(t, "caps-2"), resource.AllocateAddressRequest{}); err != nil {
				t.Fatal(err)
			}
			page, err := svc.DescribeAddresses(t.Context(), c, resource.AddressQuery{})
			if err != nil || len(page.Items) != 0 {
				t.Fatalf("DescribeAddresses = %+v, %v; want an empty page", page, err)
			}
			if network.allocates != 1 || network.describes != 0 {
				t.Errorf("backend saw %d allocates, %d describes", network.allocates, network.describes)
			}
		})
	}
}

// reached fails every read that reaches the backend.
type reachedCompute struct{ backend.Compute }

func (reachedCompute) RebootInstances(
	context.Context, backend.Mutation, resource.RebootInstancesRequest,
) (resource.Accepted[resource.InstanceStateChange], error) {
	return resource.Accepted[resource.InstanceStateChange]{}, errReached
}

func TestUnsupportedRebootIsRefusedBeforeTheBackend(t *testing.T) {
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	id, err := resource.Parse[resource.InstanceID]("i-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	svc := New(Config{
		Backends: backend.Set{Compute: reachedCompute{}},
		Capabilities: stubCapabilities{doc: resource.RegionCapabilities{
			Region: resource.RegionName, Kind: resource.RegionKindProxmox,
			Actions: map[string]resource.ActionCapability{
				resource.ActionRebootInstances.CapabilityKey(): {
					State: resource.ActionUnsupported, ReasonCode: "NoReboot", Reason: "reboot unavailable",
				},
			},
		}},
	})
	_, err = svc.RebootInstances(t.Context(), resource.Caller{Account: account}, token(t, "caps-reboot"),
		resource.RebootInstancesRequest{IDs: []resource.InstanceID{id}})
	if !resource.IsUnsupported(resource.AsError(err)) {
		t.Fatalf("RebootInstances error = %v, want UnsupportedOperation", err)
	}
}

type reachedNetwork struct{ backend.Network }

var errReached = errors.New("read reached the backend")

func (reachedCompute) DescribeInstances(
	context.Context, backend.Scope, resource.InstanceQuery,
) (resource.Page[resource.Instance], error) {
	return resource.Page[resource.Instance]{}, errReached
}

func (reachedCompute) DescribeImages(
	context.Context, backend.Scope, resource.ImageQuery,
) (resource.Page[resource.Image], error) {
	return resource.Page[resource.Image]{}, errReached
}

func (reachedCompute) DescribeVolumes(
	context.Context, backend.Scope, resource.VolumeQuery,
) (resource.Page[resource.Volume], error) {
	return resource.Page[resource.Volume]{}, errReached
}

func (reachedCompute) DescribeSnapshots(
	context.Context, backend.Scope, resource.SnapshotQuery,
) (resource.Page[resource.Snapshot], error) {
	return resource.Page[resource.Snapshot]{}, errReached
}

func (reachedCompute) DescribeKeyPairs(
	context.Context, backend.Scope, resource.KeyPairQuery,
) (resource.Page[resource.KeyPair], error) {
	return resource.Page[resource.KeyPair]{}, errReached
}

func (reachedNetwork) DescribeVpcs(
	context.Context, backend.Scope, resource.VpcQuery,
) (resource.Page[resource.Vpc], error) {
	return resource.Page[resource.Vpc]{}, errReached
}

func (reachedNetwork) DescribeSubnets(
	context.Context, backend.Scope, resource.SubnetQuery,
) (resource.Page[resource.Subnet], error) {
	return resource.Page[resource.Subnet]{}, errReached
}

func (reachedNetwork) DescribeSecurityGroups(
	context.Context, backend.Scope, resource.SecurityGroupQuery,
) (resource.Page[resource.SecurityGroup], error) {
	return resource.Page[resource.SecurityGroup]{}, errReached
}

func (reachedNetwork) DescribeAddresses(
	context.Context, backend.Scope, resource.AddressQuery,
) (resource.Page[resource.Address], error) {
	return resource.Page[resource.Address]{}, errReached
}

func TestEveryDeclaredReadIsGated(t *testing.T) {
	reads := map[resource.ReadAction]func(*Service, resource.Caller) (int, error){
		resource.ReadDescribeInstances: func(s *Service, c resource.Caller) (int, error) {
			p, err := s.DescribeInstances(t.Context(), c, resource.InstanceQuery{})
			return len(p.Items), err
		},
		resource.ReadDescribeImages: func(s *Service, c resource.Caller) (int, error) {
			p, err := s.DescribeImages(t.Context(), c, resource.ImageQuery{})
			return len(p.Items), err
		},
		resource.ReadDescribeVolumes: func(s *Service, c resource.Caller) (int, error) {
			p, err := s.DescribeVolumes(t.Context(), c, resource.VolumeQuery{})
			return len(p.Items), err
		},
		resource.ReadDescribeSnapshots: func(s *Service, c resource.Caller) (int, error) {
			p, err := s.DescribeSnapshots(t.Context(), c, resource.SnapshotQuery{})
			return len(p.Items), err
		},
		resource.ReadDescribeKeyPairs: func(s *Service, c resource.Caller) (int, error) {
			p, err := s.DescribeKeyPairs(t.Context(), c, resource.KeyPairQuery{})
			return len(p.Items), err
		},
		resource.ReadDescribeVpcs: func(s *Service, c resource.Caller) (int, error) {
			p, err := s.DescribeVpcs(t.Context(), c, resource.VpcQuery{})
			return len(p.Items), err
		},
		resource.ReadDescribeSubnets: func(s *Service, c resource.Caller) (int, error) {
			p, err := s.DescribeSubnets(t.Context(), c, resource.SubnetQuery{})
			return len(p.Items), err
		},
		resource.ReadDescribeSecurityGroups: func(s *Service, c resource.Caller) (int, error) {
			p, err := s.DescribeSecurityGroups(t.Context(), c, resource.SecurityGroupQuery{})
			return len(p.Items), err
		},
		resource.ReadDescribeAddresses: func(s *Service, c resource.Caller) (int, error) {
			p, err := s.DescribeAddresses(t.Context(), c, resource.AddressQuery{})
			return len(p.Items), err
		},
	}
	_, _, c := gatedService(t, nil)
	set := fake.New(fake.Options{}).Set()
	set.Compute, set.Network = reachedCompute{set.Compute}, reachedNetwork{set.Network}
	svc := New(Config{Backends: set, Capabilities: stubCapabilities{doc: resource.RegionCapabilities{
		Region: resource.RegionName, Kind: resource.RegionKindProxmox,
	}}})
	for _, r := range resource.ReadActions() {
		read, ok := reads[r]
		if !ok {
			t.Errorf("%s is declared but has no gated kernel read", r)
			continue
		}
		if n, err := read(svc, c); err != nil || n != 0 {
			t.Errorf("%s = %d items, %v; want an empty page", r, n, err)
		}
	}
}

func TestEmptyAddressReadLeavesInstancesWithoutPublicIP(t *testing.T) {
	doc, err := backend.AllSupported{Kind: resource.RegionKindProxmox}.RegionCapabilities(t.Context(), resource.RegionName)
	if err != nil {
		t.Fatal(err)
	}
	doc.Actions[resource.ReadDescribeAddresses.CapabilityKey()] = resource.ActionCapability{State: resource.ActionEmpty}
	svc, network, c := gatedService(t, stubCapabilities{doc: doc})
	image, err := resource.Parse[resource.ImageID]("ami-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	sub, err := svc.CreateSubnet(t.Context(), c, token(t, "caps-5"), resource.CreateSubnetRequest{Cidr: "10.3.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	run, err := svc.RunInstances(t.Context(), c, token(t, "caps-6"), resource.RunInstancesRequest{
		ImageID: image, InstanceType: "vws.small", SubnetID: sub.Items[0].ID, Count: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	alloc, err := svc.AllocateAddress(t.Context(), c, token(t, "caps-7"), resource.AllocateAddressRequest{Domain: "vpc"})
	if err != nil {
		t.Fatal(err)
	}
	assoc := resource.AssociateAddressRequest{ID: alloc.Items[0].ID, InstanceID: run.Items[0].ID}
	if _, err := svc.AssociateAddress(t.Context(), c, token(t, "caps-8"), assoc); err != nil {
		t.Fatal(err)
	}
	page, err := svc.DescribeInstances(t.Context(), c, resource.InstanceQuery{})
	if err != nil || len(page.Items) != 1 || page.Items[0].PublicIP != "" || network.describes != 0 {
		t.Fatalf("DescribeInstances = %+v, %v after %d address reads; want neither", page, err, network.describes)
	}
}

func TestSupportedAndPartialReachTheBackend(t *testing.T) {
	partial := resource.ActionCapability{State: resource.ActionPartial, ReasonCode: "Some", Reason: "some inputs"}
	svc, network, c := gatedService(t, stubCapabilities{doc: addressDoc(partial, partial)})
	if _, err := svc.AllocateAddress(t.Context(), c, token(t, "caps-3"), resource.AllocateAddressRequest{}); err != nil {
		t.Fatal(err)
	}
	page, err := svc.DescribeAddresses(t.Context(), c, resource.AddressQuery{})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("DescribeAddresses = %+v, %v", page, err)
	}
	if network.allocates != 1 || network.describes != 1 {
		t.Errorf("backend saw %d allocates, %d describes", network.allocates, network.describes)
	}
}

func TestUnreadableCapabilitiesFailClosed(t *testing.T) {
	svc, network, c := gatedService(t, stubCapabilities{err: errors.New("region unreachable")})
	if _, err := svc.AllocateAddress(t.Context(), c, token(t, "caps-4"), resource.AllocateAddressRequest{}); err == nil {
		t.Error("AllocateAddress succeeded without a document")
	}
	if _, err := svc.DescribeAddresses(t.Context(), c, resource.AddressQuery{}); err == nil {
		t.Error("DescribeAddresses succeeded without a document")
	}
	if network.allocates != 0 || network.describes != 0 {
		t.Errorf("backend saw %d allocates, %d describes", network.allocates, network.describes)
	}
}

func TestAllSupportedDeclaresEveryActionAndRead(t *testing.T) {
	doc, err := backend.AllSupported{Kind: resource.RegionKindAWS}.RegionCapabilities(t.Context(), "us-east-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, a := range resource.Actions() {
		if doc.Mutation(a).State != resource.ActionSupported {
			t.Errorf("%s is not supported", a)
		}
	}
	for _, r := range resource.ReadActions() {
		if doc.Read(r).State != resource.ActionSupported {
			t.Errorf("%s is not supported", r)
		}
	}
}
