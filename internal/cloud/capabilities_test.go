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
