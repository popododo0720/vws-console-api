package grpcclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	longrunningpb "cloud.google.com/go/longrunning/autogen/longrunningpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	commonv1 "github.com/popododo0720/vws-proto/gen/go/vws/common/v1"
	computev1 "github.com/popododo0720/vws-proto/gen/go/vws/compute/v1"
	networkv1 "github.com/popododo0720/vws-proto/gen/go/vws/network/v1"
	storagev1 "github.com/popododo0720/vws-proto/gen/go/vws/storage/v1"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/backendtest"
	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestContractOverGRPC(t *testing.T) {
	lis := bufconn.Listen(MaxMessageBytes())
	srv := grpc.NewServer(
		grpc.MaxRecvMsgSize(MaxMessageBytes()),
		grpc.MaxSendMsgSize(MaxMessageBytes()),
	)
	now := time.Unix(1_700_000_000, 0).UTC()
	world := fake.New(fake.Options{
		Now:     func() time.Time { return now },
		Entropy: &fake.Sequence{},
	})
	loop := newLoopWorld(world.Set(), now)
	computev1.RegisterInstanceServiceServer(srv, &instanceSrv{w: loop})
	computev1.RegisterKeyPairServiceServer(srv, &keySrv{w: loop})
	storagev1.RegisterVolumeServiceServer(srv, &volumeSrv{w: loop})
	storagev1.RegisterBucketServiceServer(srv, &bucketSrv{w: loop})
	storagev1.RegisterObjectServiceServer(srv, &objectSrv{w: loop})
	networkv1.RegisterVpcServiceServer(srv, &vpcSrv{w: loop})
	networkv1.RegisterSubnetServiceServer(srv, &subnetSrv{w: loop})
	networkv1.RegisterSecurityGroupServiceServer(srv, &groupSrv{w: loop})
	longrunningpb.RegisterOperationsServer(srv, &opsSrv{w: loop})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		append(dialOptions(), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}))...,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	shared := &api{
		instances:  computev1.NewInstanceServiceClient(conn),
		volumes:    storagev1.NewVolumeServiceClient(conn),
		buckets:    storagev1.NewBucketServiceClient(conn),
		objects:    storagev1.NewObjectServiceClient(conn),
		subnets:    networkv1.NewSubnetServiceClient(conn),
		vpcs:       networkv1.NewVpcServiceClient(conn),
		groups:     networkv1.NewSecurityGroupServiceClient(conn),
		keys:       computev1.NewKeyPairServiceClient(conn),
		computeOps: longrunningpb.NewOperationsClient(conn),
		storageOps: longrunningpb.NewOperationsClient(conn),
		networkOps: longrunningpb.NewOperationsClient(conn),
	}
	backendtest.Run(t, func() backend.Set {
		return backend.Set{
			Compute: computeClient{shared},
			Storage: storageClient{shared},
			Network: networkClient{shared},
		}
	})
}

// loopWorld is the resource API in front of the fake. CreateVolume and
// CreateVpc are recorded here so a child call fails when the client skipped
// them. Instance and subnet reads return the accepted snapshot until
// GetOperation, because the fake settles every read and the resource API does
// not.
type loopWorld struct {
	mu        sync.Mutex
	set       backend.Set
	now       time.Time
	idem      map[string]string
	exists    map[string]struct{}
	vpcCIDR   map[string]string
	subnetVPC map[string]string
	inst      map[string]instSnap
	sub       map[string]subSnap
	groups    map[string]resource.SecurityGroup
	opLaunch  map[string]string
}

type instSnap struct {
	inst   resource.Instance
	vpc    string
	launch string
	live   bool
}

type subSnap struct {
	sub  resource.Subnet
	vpc  string
	op   string
	live bool
}

func newLoopWorld(set backend.Set, now time.Time) *loopWorld {
	return &loopWorld{
		set: set, now: now,
		idem: map[string]string{}, exists: map[string]struct{}{},
		vpcCIDR: map[string]string{}, subnetVPC: map[string]string{},
		inst: map[string]instSnap{}, sub: map[string]subSnap{},
		groups:   map[string]resource.SecurityGroup{},
		opLaunch: map[string]string{},
	}
}

func (w *loopWorld) admit(requestID, fp, name string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if requestID != "" {
		if prev, ok := w.idem[requestID]; ok {
			if prev != fp {
				return resource.IdempotencyMismatch()
			}
			return nil
		}
	}
	if _, ok := w.exists[name]; ok {
		return &resource.Error{Code: resource.CodeAlreadyExists, Message: "already exists"}
	}
	w.exists[name] = struct{}{}
	if requestID != "" {
		w.idem[requestID] = fp
	}
	return nil
}

func (w *loopWorld) mark(name string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.exists[name] = struct{}{}
}

func (w *loopWorld) has(name string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	_, ok := w.exists[name]
	return ok
}

func (w *loopWorld) putVPC(name, cidr string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.vpcCIDR[name] = cidr
}

func (w *loopWorld) vpcOf(subnetID string) string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.subnetVPC[subnetID]
}

func (w *loopWorld) rememberSubnet(id, vpc string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.subnetVPC[id] = vpc
}

func (w *loopWorld) saveInst(snap instSnap) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.inst[snap.inst.ID.String()] = snap
}

func (w *loopWorld) saveSub(snap subSnap) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.sub[snap.sub.ID.String()] = snap
}

func (w *loopWorld) liveInst(id string, owner resource.AccountID) (instSnap, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	snap, ok := w.inst[id]
	if !ok || !snap.live || snap.inst.OwnerID != owner {
		return instSnap{}, false
	}
	return snap, true
}

func (w *loopWorld) liveSub(id string, owner resource.AccountID) (subSnap, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	snap, ok := w.sub[id]
	if !ok || !snap.live || snap.sub.OwnerID != owner {
		return subSnap{}, false
	}
	return snap, true
}

func (w *loopWorld) noteLaunch(opID, launch string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.opLaunch[opID] = launch
}

func (w *loopWorld) clearSnaps(op resource.Operation) {
	w.mu.Lock()
	defer w.mu.Unlock()
	label := w.opLaunch[op.ID.String()]
	for id, snap := range w.inst {
		if label != "" && snap.launch == label {
			snap.live = false
			w.inst[id] = snap
		}
	}
	for id, snap := range w.sub {
		if snap.op == op.ID.String() {
			snap.live = false
			w.sub[id] = snap
		}
	}
}

func (w *loopWorld) listVpcs(parent, token string, size int32) ([]*networkv1.Vpc, string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	prefix := strings.TrimRight(parent, "/") + "/vpcs/"
	names := make([]string, 0, len(w.vpcCIDR))
	for name := range w.vpcCIDR {
		if strings.HasPrefix(name, prefix) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	start := 0
	if token != "" {
		found := false
		for i, name := range names {
			if lastSegment(name) == token {
				start = i + 1
				found = true
				break
			}
		}
		if !found {
			return nil, "", resource.Invalid("pageToken", "unknown")
		}
	}
	if size <= 0 {
		size = 50
	}
	end := start + int(size)
	next := ""
	if end < len(names) {
		next = lastSegment(names[end-1])
	} else {
		end = len(names)
	}
	if start > len(names) {
		start = len(names)
	}
	out := make([]*networkv1.Vpc, 0, end-start)
	for _, name := range names[start:end] {
		out = append(out, &networkv1.Vpc{
			Name: name,
			Spec: &networkv1.VpcSpec{Ipv4Cidr: w.vpcCIDR[name]},
			Status: &networkv1.VpcStatus{
				Observed: &commonv1.ObservedState{State: commonv1.ReconciliationState_RECONCILIATION_STATE_READY},
			},
		})
	}
	return out, next, nil
}

func (w *loopWorld) lookup(ctx context.Context, name string) (resource.Operation, error) {
	projectID, err := projectOfName(name)
	if err != nil {
		return resource.Operation{}, err
	}
	account, err := accountOf(projectID)
	if err != nil {
		return resource.Operation{}, err
	}
	local, err := operationLocal(name)
	if err != nil {
		return resource.Operation{}, err
	}
	scope := backend.Scope{Account: account}
	id, err := resource.NewOperationID(resource.ServiceCompute, local)
	if err != nil {
		return resource.Operation{}, err
	}
	op, err := w.set.Compute.GetOperation(ctx, scope, id)
	if resource.CodeOf(err) == resource.CodeNotFound {
		id, err = resource.NewOperationID(resource.ServiceNetwork, local)
		if err != nil {
			return resource.Operation{}, err
		}
		op, err = w.set.Network.GetOperation(ctx, scope, id)
	}
	if err != nil {
		return resource.Operation{}, err
	}
	w.clearSnaps(op)
	return op, nil
}

type instanceSrv struct {
	computev1.UnimplementedInstanceServiceServer
	w *loopWorld
}

func (s *instanceSrv) CreateInstance(ctx context.Context, req *computev1.CreateInstanceRequest) (*longrunningpb.Operation, error) {
	spec := req.GetInstance().GetSpec()
	if spec == nil || len(spec.GetVolumes()) == 0 || !s.w.has(spec.GetVolumes()[0].GetVolume()) {
		return nil, toStatus(resource.NotFound(resource.KindInstance, "volume"))
	}
	if len(spec.GetNetworkInterfaces()) == 0 {
		return nil, toStatus(resource.Invalid("subnetId", "required"))
	}
	projectID, err := projectOfName(req.GetParent())
	if err != nil {
		return nil, toStatus(err)
	}
	account, err := accountOf(projectID)
	if err != nil {
		return nil, toStatus(err)
	}
	subID, err := resource.Parse[resource.SubnetID](lastSegment(spec.GetNetworkInterfaces()[0].GetSubnet()))
	if err != nil {
		return nil, toStatus(err)
	}
	img, err := resource.Parse[resource.ImageID](req.GetInstance().GetLabels()[labelImage])
	if err != nil {
		return nil, toStatus(err)
	}
	fp, err := protoFingerprint(req)
	if err != nil {
		return nil, toStatus(err)
	}
	acc, err := s.w.set.Compute.RunInstances(ctx, backend.Mutation{
		Scope: backend.Scope{Account: account}, Key: req.GetRequestId(), Fingerprint: fp,
	}, resource.RunInstancesRequest{
		ImageID: img, InstanceType: spec.GetMachineType(), SubnetID: subID, Count: 1,
		Tags: userTags(req.GetInstance().GetLabels()),
	})
	if err != nil {
		return nil, toStatus(err)
	}
	vpcID := vpcFromSubnet(spec.GetNetworkInterfaces()[0].GetSubnet())
	launch := req.GetInstance().GetLabels()[labelLaunch]
	if launch == "" {
		launch = acc.Operation.ID.String()
	}
	s.w.saveInst(instSnap{inst: acc.Items[0], vpc: vpcID, launch: launch, live: true})
	s.w.noteLaunch(acc.Operation.ID.String(), launch)
	return runningOp(projectID, acc.Operation, instanceName(projectID, acc.Items[0].ID.String()), commonv1.OperationVerb_OPERATION_VERB_CREATE, s.w.now)
}

func (s *instanceSrv) UpdateInstance(ctx context.Context, req *computev1.UpdateInstanceRequest) (*longrunningpb.Operation, error) {
	if volName, device, ok := dataVolume(req.GetInstance().GetSpec()); ok {
		return s.attachVolume(ctx, req, volName, device)
	}
	power := req.GetInstance().GetSpec().GetPower()
	switch power {
	case computev1.InstancePower_INSTANCE_POWER_STOPPED:
		return s.changePower(ctx, req, resource.ActionStopInstances)
	case computev1.InstancePower_INSTANCE_POWER_RUNNING:
		return s.changePower(ctx, req, resource.ActionStartInstances)
	case computev1.InstancePower_INSTANCE_POWER_UNSPECIFIED:
		return nil, toStatus(resource.Invalid("power", "unsupported"))
	default:
		return nil, toStatus(resource.Invalid("power", "unsupported"))
	}
}

func (s *instanceSrv) changePower(ctx context.Context, req *computev1.UpdateInstanceRequest, action resource.Action) (*longrunningpb.Operation, error) {
	projectID, err := projectOfName(req.GetInstance().GetName())
	if err != nil {
		return nil, toStatus(err)
	}
	account, err := accountOf(projectID)
	if err != nil {
		return nil, toStatus(err)
	}
	id, err := resource.Parse[resource.InstanceID](lastSegment(req.GetInstance().GetName()))
	if err != nil {
		return nil, toStatus(err)
	}
	fp, err := protoFingerprint(req)
	if err != nil {
		return nil, toStatus(err)
	}
	var acc resource.Accepted[resource.InstanceStateChange]
	mut := backend.Mutation{Scope: backend.Scope{Account: account}, Key: req.GetRequestId(), Fingerprint: fp}
	switch action {
	case resource.ActionStopInstances:
		acc, err = s.w.set.Compute.StopInstances(ctx, mut, resource.StopInstancesRequest{IDs: []resource.InstanceID{id}})
	case resource.ActionStartInstances:
		acc, err = s.w.set.Compute.StartInstances(ctx, mut, resource.StartInstancesRequest{IDs: []resource.InstanceID{id}})
	case resource.ActionRunInstances, resource.ActionCreateSubnet, resource.ActionCreateVpc, resource.ActionDeleteVpc,
		resource.ActionCreateVolume, resource.ActionAttachVolume, resource.ActionDeleteVolume,
		resource.ActionCreateSecurityGroup, resource.ActionAuthorizeSecurityGroupIngress,
		resource.ActionTerminateInstances, resource.ActionCreateKeyPair:
		return nil, toStatus(resource.Invalid("power", "unsupported"))
	default:
		return nil, toStatus(resource.Invalid("power", "unsupported"))
	}
	if err != nil {
		return nil, toStatus(err)
	}
	return runningOp(projectID, acc.Operation, instanceName(projectID, id.String()), commonv1.OperationVerb_OPERATION_VERB_UPDATE, s.w.now)
}

func (s *instanceSrv) attachVolume(ctx context.Context, req *computev1.UpdateInstanceRequest, volName, device string) (*longrunningpb.Operation, error) {
	projectID, err := projectOfName(req.GetInstance().GetName())
	if err != nil {
		return nil, toStatus(err)
	}
	account, err := accountOf(projectID)
	if err != nil {
		return nil, toStatus(err)
	}
	volID, err := resource.Parse[resource.VolumeID](lastSegment(volName))
	if err != nil {
		return nil, toStatus(err)
	}
	instID, err := resource.Parse[resource.InstanceID](lastSegment(req.GetInstance().GetName()))
	if err != nil {
		return nil, toStatus(err)
	}
	fp, err := protoFingerprint(req)
	if err != nil {
		return nil, toStatus(err)
	}
	acc, err := s.w.set.Compute.AttachVolume(ctx, backend.Mutation{
		Scope: backend.Scope{Account: account}, Key: req.GetRequestId(), Fingerprint: fp,
	}, resource.AttachVolumeRequest{VolumeID: volID, InstanceID: instID, Device: device})
	if err != nil {
		return nil, toStatus(err)
	}
	return runningOp(projectID, acc.Operation, volumeName(projectID, acc.Items[0].ID.String()), commonv1.OperationVerb_OPERATION_VERB_UPDATE, s.w.now)
}

func (s *instanceSrv) DeleteInstance(ctx context.Context, req *computev1.DeleteInstanceRequest) (*longrunningpb.Operation, error) {
	projectID, err := projectOfName(req.GetName())
	if err != nil {
		return nil, toStatus(err)
	}
	account, err := accountOf(projectID)
	if err != nil {
		return nil, toStatus(err)
	}
	id, err := resource.Parse[resource.InstanceID](lastSegment(req.GetName()))
	if err != nil {
		return nil, toStatus(err)
	}
	fp, err := protoFingerprint(req)
	if err != nil {
		return nil, toStatus(err)
	}
	acc, err := s.w.set.Compute.TerminateInstances(ctx, backend.Mutation{
		Scope: backend.Scope{Account: account}, Key: req.GetRequestId(), Fingerprint: fp,
	}, resource.TerminateInstancesRequest{IDs: []resource.InstanceID{id}})
	if err != nil {
		return nil, toStatus(err)
	}
	return runningOp(projectID, acc.Operation, instanceName(projectID, id.String()), commonv1.OperationVerb_OPERATION_VERB_DELETE, s.w.now)
}

func dataVolume(spec *computev1.InstanceSpec) (string, string, bool) {
	if spec == nil {
		return "", "", false
	}
	for _, vol := range spec.GetVolumes() {
		if vol.GetDeviceName() != "" && vol.GetDeviceName() != "boot" {
			return vol.GetVolume(), vol.GetDeviceName(), true
		}
	}
	return "", "", false
}

func (s *instanceSrv) GetInstance(ctx context.Context, req *computev1.GetInstanceRequest) (*computev1.Instance, error) {
	projectID, err := projectOfName(req.GetName())
	if err != nil {
		return nil, toStatus(err)
	}
	account, err := accountOf(projectID)
	if err != nil {
		return nil, toStatus(err)
	}
	idText := lastSegment(req.GetName())
	if snap, ok := s.w.liveInst(idText, account); ok {
		return instanceProto(snap.inst, projectID, snap.vpc), nil
	}
	id, err := resource.Parse[resource.InstanceID](idText)
	if err != nil {
		return nil, toStatus(err)
	}
	page, err := s.w.set.Compute.DescribeInstances(ctx, backend.Scope{Account: account}, resource.InstanceQuery{
		IDs: []resource.InstanceID{id}, Page: resource.PageRequest{Size: 1},
	})
	if err != nil {
		return nil, toStatus(err)
	}
	if len(page.Items) == 0 {
		return nil, toStatus(resource.NotFound(resource.KindInstance, idText))
	}
	inst := page.Items[0]
	return instanceProto(inst, projectID, s.w.vpcOf(inst.SubnetID.String())), nil
}

func (s *instanceSrv) ListInstances(ctx context.Context, req *computev1.ListInstancesRequest) (*computev1.ListInstancesResponse, error) {
	projectID, err := projectOfName(req.GetParent())
	if err != nil {
		return nil, toStatus(err)
	}
	account, err := accountOf(projectID)
	if err != nil {
		return nil, toStatus(err)
	}
	page, err := s.w.set.Compute.DescribeInstances(ctx, backend.Scope{Account: account}, resource.InstanceQuery{
		Page: resource.PageRequest{Size: int(req.GetPageSize()), Token: req.GetPageToken()},
	})
	if err != nil {
		return nil, toStatus(err)
	}
	items := make([]*computev1.Instance, 0, len(page.Items))
	for _, inst := range page.Items {
		items = append(items, instanceProto(inst, projectID, s.w.vpcOf(inst.SubnetID.String())))
	}
	return &computev1.ListInstancesResponse{Instances: items, NextPageToken: page.NextToken}, nil
}

type volumeSrv struct {
	storagev1.UnimplementedVolumeServiceServer
	w *loopWorld
}

func (s *volumeSrv) CreateVolume(ctx context.Context, req *storagev1.CreateVolumeRequest) (*longrunningpb.Operation, error) {
	projectID, err := projectOfName(req.GetParent())
	if err != nil {
		return nil, toStatus(err)
	}
	spec := req.GetVolume().GetSpec()
	if spec.GetImage() != "" || spec.GetSnapshot() != "" {
		name := volumeName(projectID, req.GetVolumeId())
		fp, err := protoFingerprint(req)
		if err != nil {
			return nil, toStatus(err)
		}
		if err := s.w.admit(req.GetRequestId(), fp, name); err != nil {
			return nil, toStatus(err)
		}
		return runningNamed(projectID, req.GetRequestId(), name, commonv1.OperationVerb_OPERATION_VERB_CREATE, s.w.now)
	}
	account, err := accountOf(projectID)
	if err != nil {
		return nil, toStatus(err)
	}
	fp, err := protoFingerprint(req)
	if err != nil {
		return nil, toStatus(err)
	}
	acc, err := s.w.set.Compute.CreateVolume(ctx, backend.Mutation{
		Scope: backend.Scope{Account: account}, Key: req.GetRequestId(), Fingerprint: fp,
	}, resource.CreateVolumeRequest{SizeGiB: spec.GetSizeGib(), Zone: resource.ZoneName})
	if err != nil {
		return nil, toStatus(err)
	}
	s.w.mark(volumeName(projectID, acc.Items[0].ID.String()))
	return runningOp(projectID, acc.Operation, volumeName(projectID, acc.Items[0].ID.String()), commonv1.OperationVerb_OPERATION_VERB_CREATE, s.w.now)
}

type vpcSrv struct {
	networkv1.UnimplementedVpcServiceServer
	w *loopWorld
}

func (s *vpcSrv) CreateVpc(ctx context.Context, req *networkv1.CreateVpcRequest) (*longrunningpb.Operation, error) {
	projectID, err := projectOfName(req.GetParent())
	if err != nil {
		return nil, toStatus(err)
	}
	if _, parseErr := resource.Parse[resource.VpcID](req.GetVpcId()); parseErr == nil {
		account, err := accountOf(projectID)
		if err != nil {
			return nil, toStatus(err)
		}
		fp, err := protoFingerprint(req)
		if err != nil {
			return nil, toStatus(err)
		}
		acc, err := s.w.set.Network.CreateVpc(ctx, backend.Mutation{
			Scope: backend.Scope{Account: account}, Key: req.GetRequestId(), Fingerprint: fp,
		}, resource.CreateVpcRequest{Cidr: req.GetVpc().GetSpec().GetIpv4Cidr()})
		if err != nil {
			return nil, toStatus(err)
		}
		name := vpcName(projectID, acc.Items[0].ID.String())
		s.w.mark(name)
		s.w.putVPC(name, acc.Items[0].Cidr)
		return runningOp(projectID, acc.Operation, name, commonv1.OperationVerb_OPERATION_VERB_CREATE, s.w.now)
	}
	name := vpcName(projectID, req.GetVpcId())
	fp, err := protoFingerprint(req)
	if err != nil {
		return nil, toStatus(err)
	}
	if err := s.w.admit(req.GetRequestId(), fp, name); err != nil {
		return nil, toStatus(err)
	}
	s.w.putVPC(name, req.GetVpc().GetSpec().GetIpv4Cidr())
	return runningNamed(projectID, req.GetRequestId(), name, commonv1.OperationVerb_OPERATION_VERB_CREATE, s.w.now)
}

func (s *vpcSrv) ListVpcs(_ context.Context, req *networkv1.ListVpcsRequest) (*networkv1.ListVpcsResponse, error) {
	items, next, err := s.w.listVpcs(req.GetParent(), req.GetPageToken(), req.GetPageSize())
	if err != nil {
		return nil, toStatus(err)
	}
	return &networkv1.ListVpcsResponse{Vpcs: items, NextPageToken: next}, nil
}

type subnetSrv struct {
	networkv1.UnimplementedSubnetServiceServer
	w *loopWorld
}

func (s *subnetSrv) CreateSubnet(ctx context.Context, req *networkv1.CreateSubnetRequest) (*longrunningpb.Operation, error) {
	if !s.w.has(req.GetParent()) {
		return nil, toStatus(resource.NotFound(resource.KindSubnet, "vpc"))
	}
	projectID, err := projectOfName(req.GetParent())
	if err != nil {
		return nil, toStatus(err)
	}
	account, err := accountOf(projectID)
	if err != nil {
		return nil, toStatus(err)
	}
	fp, err := protoFingerprint(req)
	if err != nil {
		return nil, toStatus(err)
	}
	vpcID := lastSegment(req.GetParent())
	var vpcRef resource.VpcID
	if parsed, parseErr := resource.Parse[resource.VpcID](vpcID); parseErr == nil {
		vpcRef = parsed
	}
	acc, err := s.w.set.Network.CreateSubnet(ctx, backend.Mutation{
		Scope: backend.Scope{Account: account}, Key: req.GetRequestId(), Fingerprint: fp,
	}, resource.CreateSubnetRequest{Cidr: req.GetSubnet().GetSpec().GetIpv4Cidr(), VpcID: vpcRef})
	if err != nil {
		return nil, toStatus(err)
	}
	s.w.rememberSubnet(acc.Items[0].ID.String(), vpcID)
	s.w.saveSub(subSnap{sub: acc.Items[0], vpc: vpcID, op: acc.Operation.ID.String(), live: true})
	return runningOp(projectID, acc.Operation, subnetName(projectID, vpcID, acc.Items[0].ID.String()), commonv1.OperationVerb_OPERATION_VERB_CREATE, s.w.now)
}

func (s *subnetSrv) GetSubnet(ctx context.Context, req *networkv1.GetSubnetRequest) (*networkv1.Subnet, error) {
	projectID, err := projectOfName(req.GetName())
	if err != nil {
		return nil, toStatus(err)
	}
	account, err := accountOf(projectID)
	if err != nil {
		return nil, toStatus(err)
	}
	idText := lastSegment(req.GetName())
	if snap, ok := s.w.liveSub(idText, account); ok {
		return subnetProto(snap.sub, projectID, snap.vpc), nil
	}
	id, err := resource.Parse[resource.SubnetID](idText)
	if err != nil {
		return nil, toStatus(err)
	}
	page, err := s.w.set.Network.DescribeSubnets(ctx, backend.Scope{Account: account}, resource.SubnetQuery{
		IDs: []resource.SubnetID{id}, Page: resource.PageRequest{Size: 1},
	})
	if err != nil {
		return nil, toStatus(err)
	}
	if len(page.Items) == 0 {
		return nil, toStatus(resource.NotFound(resource.KindSubnet, idText))
	}
	return subnetProto(page.Items[0], projectID, s.w.vpcOf(idText)), nil
}

func (s *subnetSrv) ListSubnets(ctx context.Context, req *networkv1.ListSubnetsRequest) (*networkv1.ListSubnetsResponse, error) {
	projectID, err := projectOfName(req.GetParent())
	if err != nil {
		return nil, toStatus(err)
	}
	account, err := accountOf(projectID)
	if err != nil {
		return nil, toStatus(err)
	}
	if req.GetPageToken() != "" {
		return nil, toStatus(resource.Invalid("pageToken", "unknown"))
	}
	vpcID := lastSegment(req.GetParent())
	page, err := s.w.set.Network.DescribeSubnets(ctx, backend.Scope{Account: account}, resource.SubnetQuery{
		Page: resource.PageRequest{Size: 100},
	})
	if err != nil {
		return nil, toStatus(err)
	}
	items := make([]*networkv1.Subnet, 0, len(page.Items))
	for _, sub := range page.Items {
		if s.w.vpcOf(sub.ID.String()) != vpcID {
			continue
		}
		items = append(items, subnetProto(sub, projectID, vpcID))
	}
	return &networkv1.ListSubnetsResponse{Subnets: items}, nil
}

type bucketSrv struct {
	storagev1.UnimplementedBucketServiceServer
	w *loopWorld
}

func (s *bucketSrv) CreateBucket(ctx context.Context, req *storagev1.CreateBucketRequest) (*longrunningpb.Operation, error) {
	projectID, err := projectOfName(req.GetParent())
	if err != nil {
		return nil, toStatus(err)
	}
	account, err := accountOf(projectID)
	if err != nil {
		return nil, toStatus(err)
	}
	name, err := resource.Parse[resource.BucketName](req.GetBucketId())
	if err != nil {
		return nil, toStatus(err)
	}
	bucket, err := s.w.set.Storage.CreateBucket(ctx, backend.Scope{Account: account}, name)
	if err != nil {
		return nil, toStatus(err)
	}
	return doneResource(projectID, req.GetRequestId(), bucketName(projectID, name.String()), bucketProto(bucket, projectID), s.w.now)
}

func (s *bucketSrv) GetBucket(ctx context.Context, req *storagev1.GetBucketRequest) (*storagev1.Bucket, error) {
	projectID, account, name, err := bucketRef(req.GetName())
	if err != nil {
		return nil, toStatus(err)
	}
	bucket, err := s.w.set.Storage.GetBucket(ctx, backend.Scope{Account: account}, name)
	if err != nil {
		return nil, toStatus(err)
	}
	return bucketProto(bucket, projectID), nil
}

func (s *bucketSrv) ListBuckets(ctx context.Context, req *storagev1.ListBucketsRequest) (*storagev1.ListBucketsResponse, error) {
	projectID, err := projectOfName(req.GetParent())
	if err != nil {
		return nil, toStatus(err)
	}
	account, err := accountOf(projectID)
	if err != nil {
		return nil, toStatus(err)
	}
	page, err := s.w.set.Storage.ListBuckets(ctx, backend.Scope{Account: account}, resource.BucketQuery{
		Page: resource.PageRequest{Size: int(req.GetPageSize()), Token: req.GetPageToken()},
	})
	if err != nil {
		return nil, toStatus(err)
	}
	items := make([]*storagev1.Bucket, 0, len(page.Items))
	for _, bucket := range page.Items {
		items = append(items, bucketProto(bucket, projectID))
	}
	return &storagev1.ListBucketsResponse{Buckets: items, NextPageToken: page.NextToken}, nil
}

func (s *bucketSrv) DeleteBucket(ctx context.Context, req *storagev1.DeleteBucketRequest) (*longrunningpb.Operation, error) {
	projectID, account, name, err := bucketRef(req.GetName())
	if err != nil {
		return nil, toStatus(err)
	}
	if err := s.w.set.Storage.DeleteBucket(ctx, backend.Scope{Account: account}, name); err != nil {
		return nil, toStatus(err)
	}
	return doneResource(projectID, req.GetRequestId(), req.GetName(), bucketProto(resource.Bucket{Name: name, OwnerID: account}, projectID), s.w.now)
}

type objectSrv struct {
	storagev1.UnimplementedObjectServiceServer
	w *loopWorld
}

func (s *objectSrv) GetObject(ctx context.Context, req *storagev1.GetObjectRequest) (*storagev1.Object, error) {
	projectID, account, bucket, key, err := objectRef(req.GetName())
	if err != nil {
		return nil, toStatus(err)
	}
	obj, rc, err := s.w.set.Storage.GetObject(ctx, backend.Scope{Account: account}, resource.GetObjectRequest{Bucket: bucket, Key: key})
	if err != nil {
		return nil, toStatus(err)
	}
	_ = rc.Close()
	return objectProto(obj, projectID), nil
}

func (s *objectSrv) UpdateObject(ctx context.Context, req *storagev1.UpdateObjectRequest) (*longrunningpb.Operation, error) {
	projectID, account, bucket, key, err := objectRef(req.GetObject().GetName())
	if err != nil {
		return nil, toStatus(err)
	}
	obj, err := s.w.set.Storage.PutObject(ctx, backend.Scope{Account: account}, resource.PutObjectRequest{
		Bucket: bucket, Key: key, ContentType: req.GetObject().GetSpec().GetContentType(), Size: int64(len(req.GetContents())),
	}, bytes.NewReader(req.GetContents()))
	if err != nil {
		return nil, toStatus(err)
	}
	return doneResource(projectID, req.GetRequestId(), req.GetObject().GetName(), objectProto(obj, projectID), s.w.now)
}

func (s *objectSrv) DeleteObject(ctx context.Context, req *storagev1.DeleteObjectRequest) (*longrunningpb.Operation, error) {
	projectID, account, bucket, key, err := objectRef(req.GetName())
	if err != nil {
		return nil, toStatus(err)
	}
	if err := s.w.set.Storage.DeleteObject(ctx, backend.Scope{Account: account}, bucket, key); err != nil {
		return nil, toStatus(err)
	}
	return doneResource(projectID, req.GetRequestId(), req.GetName(), &storagev1.Object{Name: req.GetName()}, s.w.now)
}

type opsSrv struct {
	longrunningpb.UnimplementedOperationsServer
	w *loopWorld
}

func (s *opsSrv) GetOperation(ctx context.Context, req *longrunningpb.GetOperationRequest) (*longrunningpb.Operation, error) {
	op, err := s.w.lookup(ctx, req.GetName())
	if err != nil {
		return nil, toStatus(err)
	}
	projectID, err := projectOfName(req.GetName())
	if err != nil {
		return nil, toStatus(err)
	}
	resourceName := ""
	verb := commonv1.OperationVerb_OPERATION_VERB_CREATE
	if op.Action == resource.ActionStopInstances {
		verb = commonv1.OperationVerb_OPERATION_VERB_UPDATE
	}
	if len(op.Targets) > 0 {
		resourceName = targetName(projectID, op.Targets[0], s.w.vpcOf(op.Targets[0].ID()))
	}
	msg, err := runningOp(projectID, op, resourceName, verb, op.CreateTime)
	if err != nil {
		return nil, err
	}
	switch op.State {
	case resource.OperationSucceeded:
		msg.Done = true
	case resource.OperationFailed:
		msg.Done = true
		if op.Error != nil {
			msg.Result = &longrunningpb.Operation_Error{Error: status.Convert(toStatus(op.Error)).Proto()}
		}
	case resource.OperationRunning:
	default:
		return nil, toStatus(resource.Internal(strErr("bad operation state")))
	}
	return msg, nil
}

func runningOp(projectID string, op resource.Operation, resourceName string, verb commonv1.OperationVerb, now time.Time) (*longrunningpb.Operation, error) {
	msg, err := longOp(projectID, op.ID.Local(), resourceName, op.Action.String(), verb, now)
	if err != nil {
		return nil, toStatus(err)
	}
	return msg, nil
}

func runningNamed(projectID, requestID, resourceName string, verb commonv1.OperationVerb, now time.Time) (*longrunningpb.Operation, error) {
	local := strings.ReplaceAll(requestID, "-", "")
	if len(local) > 32 {
		local = local[:32]
	}
	return longOp(projectID, local, resourceName, requestID, verb, now)
}

func doneResource(projectID, requestID, resourceName string, msg proto.Message, now time.Time) (*longrunningpb.Operation, error) {
	op, err := runningNamed(projectID, requestID, resourceName, commonv1.OperationVerb_OPERATION_VERB_CREATE, now)
	if err != nil {
		return nil, toStatus(err)
	}
	body, err := anypb.New(msg)
	if err != nil {
		return nil, toStatus(err)
	}
	op.Done = true
	op.Result = &longrunningpb.Operation_Response{Response: body}
	return op, nil
}

func targetName(projectID string, ref resource.Ref, vpcID string) string {
	switch ref.Kind() {
	case resource.KindInstance:
		return instanceName(projectID, ref.ID())
	case resource.KindSubnet:
		return subnetName(projectID, vpcID, ref.ID())
	case resource.KindVpc:
		return vpcName(projectID, ref.ID())
	case resource.KindVolume:
		return volumeName(projectID, ref.ID())
	case resource.KindSecurityGroup:
		return securityGroupName(projectID, vpcID, ref.ID())
	case resource.KindKeyPair:
		return keyPairName(projectID, ref.ID())
	case resource.KindImage, resource.KindReservation, resource.KindBucket, resource.KindObject, resource.KindOperation, resource.KindUnspecified:
		return ""
	default:
		return ""
	}
}

func vpcFromSubnet(name string) string {
	parts := splitSlash(name)
	for i, part := range parts {
		if part == "vpcs" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

func bucketRef(name string) (string, resource.AccountID, resource.BucketName, error) {
	parts := splitSlash(name)
	if len(parts) != 4 || parts[2] != "buckets" {
		return "", resource.AccountID{}, resource.BucketName{}, resource.Internal(strErr("bad bucket name"))
	}
	account, err := accountOf(parts[1])
	if err != nil {
		return "", resource.AccountID{}, resource.BucketName{}, err
	}
	bucket, err := resource.Parse[resource.BucketName](parts[3])
	if err != nil {
		return "", resource.AccountID{}, resource.BucketName{}, err
	}
	return parts[1], account, bucket, nil
}

func objectRef(name string) (string, resource.AccountID, resource.BucketName, resource.ObjectKey, error) {
	parts := splitSlash(name)
	if len(parts) != 6 || parts[2] != "buckets" || parts[4] != "objects" {
		return "", resource.AccountID{}, resource.BucketName{}, resource.ObjectKey{}, resource.Internal(strErr("bad object name"))
	}
	account, err := accountOf(parts[1])
	if err != nil {
		return "", resource.AccountID{}, resource.BucketName{}, resource.ObjectKey{}, err
	}
	bucket, err := resource.Parse[resource.BucketName](parts[3])
	if err != nil {
		return "", resource.AccountID{}, resource.BucketName{}, resource.ObjectKey{}, err
	}
	keyText, err := decodeObjectKey(parts[5])
	if err != nil {
		return "", resource.AccountID{}, resource.BucketName{}, resource.ObjectKey{}, err
	}
	key, err := resource.Parse[resource.ObjectKey](keyText)
	if err != nil {
		return "", resource.AccountID{}, resource.BucketName{}, resource.ObjectKey{}, err
	}
	return parts[1], account, bucket, key, nil
}

func protoFingerprint(msg proto.Message) (string, error) {
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(msg)
	if err != nil {
		return "", resource.Internal(err)
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:]), nil
}
