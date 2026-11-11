package backendtest

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	b "github.com/popododo0720/vws-console-api/internal/backend"
	r "github.com/popododo0720/vws-console-api/internal/resource"
)

type capsStub struct {
	items       int
	token       string
	err         error
	mutationErr error
}

func (s capsStub) RebootInstances(context.Context, b.Mutation,
	r.RebootInstancesRequest,
) (r.Accepted[r.InstanceStateChange], error) {
	return r.Accepted[r.InstanceStateChange]{}, s.mutationErr
}

func (s capsStub) RunInstances(context.Context, b.Mutation, r.RunInstancesRequest) (r.Accepted[r.Instance], error) {
	return r.Accepted[r.Instance]{}, s.mutationErr
}

func (s capsStub) StopInstances(context.Context, b.Mutation,
	r.StopInstancesRequest,
) (r.Accepted[r.InstanceStateChange], error) {
	return r.Accepted[r.InstanceStateChange]{}, s.mutationErr
}

func (s capsStub) StartInstances(context.Context, b.Mutation,
	r.StartInstancesRequest,
) (r.Accepted[r.InstanceStateChange], error) {
	return r.Accepted[r.InstanceStateChange]{}, s.mutationErr
}

func (s capsStub) TerminateInstances(context.Context, b.Mutation,
	r.TerminateInstancesRequest,
) (r.Accepted[r.InstanceStateChange], error) {
	return r.Accepted[r.InstanceStateChange]{}, s.mutationErr
}

func (s capsStub) DescribeInstances(context.Context, b.Scope, r.InstanceQuery) (r.Page[r.Instance], error) {
	return r.Page[r.Instance]{Items: make([]r.Instance, s.items), NextToken: s.token}, s.err
}

func (s capsStub) CreateTags(context.Context, b.Mutation, r.CreateTagsRequest) (r.Accepted[r.Instance], error) {
	return r.Accepted[r.Instance]{}, s.mutationErr
}

func (s capsStub) TagVolumes(context.Context, b.Mutation, r.TagVolumesRequest) (r.Accepted[r.Volume], error) {
	return r.Accepted[r.Volume]{}, s.mutationErr
}

func (s capsStub) DeleteTags(context.Context, b.Mutation, r.DeleteTagsRequest) (r.Accepted[r.Instance], error) {
	return r.Accepted[r.Instance]{}, s.mutationErr
}

func (s capsStub) CreateVolume(context.Context, b.Mutation, r.CreateVolumeRequest) (r.Accepted[r.Volume], error) {
	return r.Accepted[r.Volume]{}, s.mutationErr
}

func (s capsStub) AttachVolume(context.Context, b.Mutation, r.AttachVolumeRequest) (r.Accepted[r.Volume], error) {
	return r.Accepted[r.Volume]{}, s.mutationErr
}

func (s capsStub) DetachVolume(context.Context, b.Mutation,
	r.DetachVolumeRequest,
) (r.Accepted[r.VolumeAttachment], error) {
	return r.Accepted[r.VolumeAttachment]{}, s.mutationErr
}

func (s capsStub) DeleteVolume(context.Context, b.Mutation, r.DeleteVolumeRequest) (r.Accepted[r.Volume], error) {
	return r.Accepted[r.Volume]{}, s.mutationErr
}

func (s capsStub) ModifyVolume(context.Context, b.Mutation, r.ModifyVolumeRequest) (r.Accepted[r.Volume], error) {
	return r.Accepted[r.Volume]{}, s.mutationErr
}

func (s capsStub) DescribeVolumes(context.Context, b.Scope, r.VolumeQuery) (r.Page[r.Volume], error) {
	return r.Page[r.Volume]{Items: make([]r.Volume, s.items), NextToken: s.token}, s.err
}

func (s capsStub) DescribeImages(context.Context, b.Scope, r.ImageQuery) (r.Page[r.Image], error) {
	return r.Page[r.Image]{Items: make([]r.Image, s.items), NextToken: s.token}, s.err
}

func (s capsStub) CreateKeyPair(context.Context, b.Mutation, r.CreateKeyPairRequest) (r.Accepted[r.KeyPair], error) {
	return r.Accepted[r.KeyPair]{}, s.mutationErr
}

func (s capsStub) DeleteKeyPair(context.Context, b.Mutation, r.DeleteKeyPairRequest) (r.Accepted[r.KeyPair], error) {
	return r.Accepted[r.KeyPair]{}, s.mutationErr
}

func (s capsStub) DescribeKeyPairs(context.Context, b.Scope, r.KeyPairQuery) (r.Page[r.KeyPair], error) {
	return r.Page[r.KeyPair]{Items: make([]r.KeyPair, s.items), NextToken: s.token}, s.err
}

func (s capsStub) CreateSnapshot(context.Context, b.Mutation, r.CreateSnapshotRequest) (r.Accepted[r.Snapshot], error) {
	return r.Accepted[r.Snapshot]{}, s.mutationErr
}

func (s capsStub) DeleteSnapshot(context.Context, b.Mutation, r.DeleteSnapshotRequest) (r.Accepted[r.Snapshot], error) {
	return r.Accepted[r.Snapshot]{}, s.mutationErr
}

func (s capsStub) DescribeSnapshots(context.Context, b.Scope, r.SnapshotQuery) (r.Page[r.Snapshot], error) {
	return r.Page[r.Snapshot]{Items: make([]r.Snapshot, s.items), NextToken: s.token}, s.err
}

func (s capsStub) RegisterImage(context.Context, b.Mutation, r.RegisterImageRequest) (r.Accepted[r.Image], error) {
	return r.Accepted[r.Image]{}, s.mutationErr
}

func (s capsStub) CreateSubnet(context.Context, b.Mutation, r.CreateSubnetRequest) (r.Accepted[r.Subnet], error) {
	return r.Accepted[r.Subnet]{}, s.mutationErr
}

func (s capsStub) DescribeSubnets(context.Context, b.Scope, r.SubnetQuery) (r.Page[r.Subnet], error) {
	return r.Page[r.Subnet]{Items: make([]r.Subnet, s.items), NextToken: s.token}, s.err
}

func (s capsStub) CreateVpc(context.Context, b.Mutation, r.CreateVpcRequest) (r.Accepted[r.Vpc], error) {
	return r.Accepted[r.Vpc]{}, s.mutationErr
}

func (s capsStub) DeleteVpc(context.Context, b.Mutation, r.DeleteVpcRequest) (r.Accepted[r.Vpc], error) {
	return r.Accepted[r.Vpc]{}, s.mutationErr
}

func (s capsStub) DescribeVpcs(context.Context, b.Scope, r.VpcQuery) (r.Page[r.Vpc], error) {
	return r.Page[r.Vpc]{Items: make([]r.Vpc, s.items), NextToken: s.token}, s.err
}

func (s capsStub) TagVpcs(context.Context, b.Mutation, r.TagVpcsRequest) (r.Accepted[r.Vpc], error) {
	return r.Accepted[r.Vpc]{}, s.mutationErr
}

func (s capsStub) TagSubnets(context.Context, b.Mutation, r.TagSubnetsRequest) (r.Accepted[r.Subnet], error) {
	return r.Accepted[r.Subnet]{}, s.mutationErr
}

func (s capsStub) UntagVpcs(context.Context, b.Mutation, r.UntagVpcsRequest) (r.Accepted[r.Vpc], error) {
	return r.Accepted[r.Vpc]{}, s.mutationErr
}

func (s capsStub) UntagSubnets(context.Context, b.Mutation, r.UntagSubnetsRequest) (r.Accepted[r.Subnet], error) {
	return r.Accepted[r.Subnet]{}, s.mutationErr
}

func (s capsStub) CreateSecurityGroup(context.Context, b.Mutation,
	r.CreateSecurityGroupRequest,
) (r.Accepted[r.SecurityGroup], error) {
	return r.Accepted[r.SecurityGroup]{}, s.mutationErr
}

func (s capsStub) DeleteSecurityGroup(context.Context, b.Mutation,
	r.DeleteSecurityGroupRequest,
) (r.Accepted[r.SecurityGroup], error) {
	return r.Accepted[r.SecurityGroup]{}, s.mutationErr
}

func (s capsStub) DescribeSecurityGroups(context.Context, b.Scope,
	r.SecurityGroupQuery,
) (r.Page[r.SecurityGroup], error) {
	return r.Page[r.SecurityGroup]{Items: make([]r.SecurityGroup, s.items), NextToken: s.token}, s.err
}

func (s capsStub) AuthorizeSecurityGroupIngress(context.Context, b.Mutation,
	r.AuthorizeSecurityGroupIngressRequest,
) (r.Accepted[r.SecurityGroup], error) {
	return r.Accepted[r.SecurityGroup]{}, s.mutationErr
}

func (s capsStub) RevokeSecurityGroupIngress(context.Context, b.Mutation,
	r.RevokeSecurityGroupIngressRequest,
) (r.Accepted[r.SecurityGroup], error) {
	return r.Accepted[r.SecurityGroup]{}, s.mutationErr
}

func (s capsStub) DeleteSubnet(context.Context, b.Mutation, r.DeleteSubnetRequest) (r.Accepted[r.Subnet], error) {
	return r.Accepted[r.Subnet]{}, s.mutationErr
}

func (s capsStub) AllocateAddress(context.Context, b.Mutation,
	r.AllocateAddressRequest,
) (r.Accepted[r.Address], error) {
	return r.Accepted[r.Address]{}, s.mutationErr
}

func (s capsStub) ReleaseAddress(context.Context, b.Mutation, r.ReleaseAddressRequest) (r.Accepted[r.Address], error) {
	return r.Accepted[r.Address]{}, s.mutationErr
}

func (s capsStub) DescribeAddresses(context.Context, b.Scope, r.AddressQuery) (r.Page[r.Address], error) {
	return r.Page[r.Address]{Items: make([]r.Address, s.items), NextToken: s.token}, s.err
}

func (s capsStub) AssociateAddress(context.Context, b.Mutation,
	r.AssociateAddressRequest,
) (r.Accepted[r.Address], error) {
	return r.Accepted[r.Address]{}, s.mutationErr
}

func (s capsStub) DisassociateAddress(context.Context, b.Mutation,
	r.DisassociateAddressRequest,
) (r.Accepted[r.Address], error) {
	return r.Accepted[r.Address]{}, s.mutationErr
}

func (s capsStub) GetOperation(context.Context, b.Scope, r.OperationID) (r.Operation, error) {
	return r.Operation{}, nil
}

type capabilityRecorder struct{ failures []string }

type runStub struct {
	capsStub
	*capabilityRecorder
	calls int
}

func (s *runStub) AllocateAddress(
	context.Context,
	b.Mutation,
	r.AllocateAddressRequest,
) (r.Accepted[r.Address], error) {
	s.calls++
	return r.Accepted[r.Address]{}, s.mutationErr
}

func (s *runStub) DescribeAddresses(context.Context, b.Scope, r.AddressQuery) (r.Page[r.Address], error) {
	s.calls++
	return r.Page[r.Address]{Items: make([]r.Address, s.items)}, nil
}

func TestRunCapabilities(t *testing.T) {
	if mode := os.Getenv("VWS_RUN_CAPABILITIES"); mode != "" {
		caps, err := (b.AllSupported{Kind: r.RegionKindAWS}).RegionCapabilities(t.Context(), r.RegionName)
		if err != nil {
			t.Fatal(err)
		}
		caps.Actions[r.ActionAllocateAddress.CapabilityKey()] = r.ActionCapability{
			State: r.ActionUnsupported, Reason: "no elastic IP", ReasonCode: "NoElasticIP",
		}
		caps.Actions[r.ReadDescribeAddresses.CapabilityKey()] = r.ActionCapability{State: r.ActionEmpty}
		stub := &runStub{
			capsStub:           capsStub{mutationErr: r.Unsupported("AllocateAddress", "no elastic IP")},
			capabilityRecorder: &capabilityRecorder{},
		}
		if mode == "mutation" {
			stub.mutationErr = nil
		}
		if mode == "read" {
			stub.items = 1
		}
		Run(t, func() b.Set { return b.Set{Compute: stub, Network: stub} }, caps)
		if stub.calls != 2 {
			stub.Errorf("public Run made %d capability calls, want 2", stub.calls)
		}
		for _, failure := range stub.failures {
			t.Error(failure)
		}
		return
	}
	for _, mode := range []string{"good", "mutation", "read"} {
		cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestRunCapabilities$/^Capabilities$", "-test.v")
		cmd.Env = append(os.Environ(), "VWS_RUN_CAPABILITIES="+mode)
		out, err := cmd.CombinedOutput()
		want := "--- PASS: TestRunCapabilities/Capabilities"
		if mode != "good" {
			want = "--- FAIL: TestRunCapabilities/Capabilities"
		}
		if (err == nil) != (mode == "good") || !strings.Contains(string(out), want) {
			t.Fatalf("%s: %v\n%s", mode, err, out)
		}
	}
}

func (*capabilityRecorder) Helper() {}
func (r *capabilityRecorder) Errorf(format string, args ...any) {
	r.failures = append(r.failures, fmt.Sprintf(format, args...))
}

func TestCapabilityContract(t *testing.T) {
	caps := r.RegionCapabilities{Region: r.RegionName, Kind: r.RegionKindProxmox}
	good := capsStub{mutationErr: r.Unsupported("action", "not supported")}
	for _, tc := range []struct {
		name     string
		stub     capsStub
		failures int
	}{
		{"unsupported and empty", good, 0},
		{"data on empty reads", capsStub{items: 1, mutationErr: good.mutationErr}, len(r.ReadActions())},
		{"token on empty reads", capsStub{token: "next", mutationErr: good.mutationErr}, len(r.ReadActions())},
		{
			"read errors",
			capsStub{err: r.Invalid("read", "bad"), mutationErr: good.mutationErr},
			len(r.ReadActions()),
		},
		{"mutation succeeds", capsStub{}, 34},
		{"wrong invalid argument", capsStub{mutationErr: r.Invalid("action", "bad")}, 34},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := &capabilityRecorder{}
			capabilityContract(recorder, b.Set{Compute: tc.stub, Network: tc.stub}, caps)
			if len(recorder.failures) != tc.failures {
				t.Fatalf("failures=%d want=%d: %v", len(recorder.failures), tc.failures, recorder.failures)
			}
		})
	}
}

func TestCapabilityProbeTablesCoverEveryAction(t *testing.T) {
	stub := capsStub{}
	ctx := context.Background()
	mutations := mutationProbes(ctx, b.Set{Compute: stub, Network: stub}, b.Mutation{})
	if len(mutations) != len(r.Actions()) {
		t.Fatalf("mutation table has %d entries for %d actions", len(mutations), len(r.Actions()))
	}
	for _, action := range r.Actions() {
		if len(mutations[action]) == 0 {
			t.Errorf("missing mutation %s", action)
		}
	}
	reads := readProbes(ctx, b.Set{Compute: stub, Network: stub}, b.Scope{})
	if len(reads) != len(r.ReadActions()) {
		t.Fatalf("read table has %d entries for %d actions", len(reads), len(r.ReadActions()))
	}
	for _, action := range r.ReadActions() {
		if reads[action] == nil {
			t.Errorf("missing read %s", action)
		}
	}
}

func TestCapabilitySkipsNameActionAndReason(t *testing.T) {
	if os.Getenv("VWS_CAPABILITY_SKIP_CHILD") == "1" {
		for _, state := range []r.ActionState{r.ActionUnsupported, r.ActionEmpty} {
			t.Run(state.String(), func(t *testing.T) {
				caps := r.RegionCapabilities{Actions: map[string]r.ActionCapability{}}
				if state == r.ActionUnsupported {
					caps.Actions[r.ActionRunInstances.CapabilityKey()] = r.ActionCapability{
						State: state, Reason: "no VM creation", ReasonCode: "ReadOnly",
					}
					requireCapabilities(t, caps, []r.Action{r.ActionRunInstances}, nil)
				} else {
					requireCapabilities(t, caps, nil, []r.ReadAction{r.ReadDescribeInstances})
				}
				t.Fatal("unsupported group ran")
			})
		}
		return
	}
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestCapabilitySkipsNameActionAndReason$", "-test.v")
	cmd.Env = append(os.Environ(), "VWS_CAPABILITY_SKIP_CHILD=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("skip child: %v\n%s", err, output)
	}
	for _, want := range []string{
		"--- SKIP:", "ec2:RunInstances: no VM creation", "ec2:DescribeInstances: region declares an empty read",
	} {
		if !strings.Contains(string(output), want) {
			t.Fatalf("missing %q in output:\n%s", want, output)
		}
	}
}

func TestPartialCapabilitiesRun(t *testing.T) {
	caps := r.RegionCapabilities{Actions: map[string]r.ActionCapability{
		r.ActionRunInstances.CapabilityKey(): {
			State: r.ActionPartial, Reason: "templates only", ReasonCode: "TemplateOnly",
		},
		r.ReadDescribeInstances.CapabilityKey(): {State: r.ActionSupported},
	}}
	ran := false
	t.Run("partial", func(t *testing.T) {
		requireCapabilities(t, caps, []r.Action{r.ActionRunInstances},
			[]r.ReadAction{r.ReadDescribeInstances})
		ran = true
	})
	if !ran {
		t.Fatal("partial group was skipped")
	}
}
