package grpcclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"maps"
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
	now := time.Unix(1_700_000_000, 0).UTC()
	world := fake.New(fake.Options{
		Now:     func() time.Time { return now },
		Entropy: &fake.Sequence{},
	})
	harness := dialLoopback(t, world, now)
	backendtest.Run(t, harness)
	// The #213 DetachVolume client-token table, in its own account.
	t.Run("DetachReplay", func(t *testing.T) { backendtest.DetachReplay(t, harness) })
}

// dialLoopback serves world through the loopback resource API on bufconn,
// compute and storage on separate listeners, and returns a harness of
// clients for it. now stamps the operations the loopback mints.
func dialLoopback(t *testing.T, world *fake.World, now time.Time) backendtest.Harness {
	t.Helper()
	computeLis := bufconn.Listen(MaxMessageBytes())
	storageLis := bufconn.Listen(MaxMessageBytes())
	computeSrv := grpc.NewServer(
		grpc.MaxRecvMsgSize(MaxMessageBytes()),
		grpc.MaxSendMsgSize(MaxMessageBytes()),
	)
	storageSrv := grpc.NewServer(
		grpc.MaxRecvMsgSize(MaxMessageBytes()),
		grpc.MaxSendMsgSize(MaxMessageBytes()),
	)
	loop := newLoopWorld(world.Set(), now)
	computev1.RegisterInstanceServiceServer(computeSrv, &instanceSrv{w: loop})
	computev1.RegisterKeyPairServiceServer(computeSrv, &keySrv{w: loop})
	networkv1.RegisterAddressServiceServer(computeSrv, &addressSrv{w: loop})
	networkv1.RegisterVpcServiceServer(computeSrv, &vpcSrv{w: loop})
	networkv1.RegisterSubnetServiceServer(computeSrv, &subnetSrv{w: loop})
	networkv1.RegisterSecurityGroupServiceServer(computeSrv, &groupSrv{w: loop})
	longrunningpb.RegisterOperationsServer(computeSrv, opsGate{opsSrv: opsSrv{w: loop}, volumes: false})
	storagev1.RegisterVolumeServiceServer(storageSrv, &volumeSrv{w: loop})
	storagev1.RegisterBucketServiceServer(storageSrv, &bucketSrv{w: loop})
	storagev1.RegisterObjectServiceServer(storageSrv, &objectSrv{w: loop})
	storagev1.RegisterSnapshotServiceServer(storageSrv, &snapshotSrv{w: loop})
	longrunningpb.RegisterOperationsServer(storageSrv, opsGate{opsSrv: opsSrv{w: loop}, volumes: true})
	go func() { _ = computeSrv.Serve(computeLis) }()
	go func() { _ = storageSrv.Serve(storageLis) }()
	t.Cleanup(computeSrv.Stop)
	t.Cleanup(storageSrv.Stop)

	dial := func(ctx context.Context, addr string) (net.Conn, error) {
		if strings.Contains(addr, "storage") {
			return storageLis.DialContext(ctx)
		}
		return computeLis.DialContext(ctx)
	}
	computeConn, err := grpc.NewClient("passthrough:///compute",
		append(dialOptions(), grpc.WithContextDialer(dial))...,
	)
	if err != nil {
		t.Fatal(err)
	}
	storageConn, err := grpc.NewClient("passthrough:///storage",
		append(dialOptions(), grpc.WithContextDialer(dial))...,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = computeConn.Close() })
	t.Cleanup(func() { _ = storageConn.Close() })
	shared := &api{
		instances:  computev1.NewInstanceServiceClient(computeConn),
		volumes:    storagev1.NewVolumeServiceClient(storageConn),
		buckets:    storagev1.NewBucketServiceClient(storageConn),
		objects:    storagev1.NewObjectServiceClient(storageConn),
		subnets:    networkv1.NewSubnetServiceClient(computeConn),
		vpcs:       networkv1.NewVpcServiceClient(computeConn),
		groups:     networkv1.NewSecurityGroupServiceClient(computeConn),
		keys:       computev1.NewKeyPairServiceClient(computeConn),
		addresses:  networkv1.NewAddressServiceClient(computeConn),
		snapshots:  storagev1.NewSnapshotServiceClient(storageConn),
		computeOps: longrunningpb.NewOperationsClient(computeConn),
		storageOps: longrunningpb.NewOperationsClient(storageConn),
		networkOps: longrunningpb.NewOperationsClient(computeConn),
	}
	return func() backend.Set {
		return backend.Set{
			Compute: computeClient{shared},
			Storage: storageClient{shared},
			Network: networkClient{shared},
		}
	}
}

// opsGate hides volume operations from the compute listener and every other
// operation from the storage listener. A client that polls the wrong service
// gets NotFound.
type opsGate struct {
	opsSrv
	volumes bool
}

func (s opsGate) GetOperation(ctx context.Context, req *longrunningpb.GetOperationRequest) (*longrunningpb.Operation, error) {
	op, err := s.w.lookup(ctx, req.GetName())
	if err != nil {
		return nil, toStatus(err)
	}
	volume := op.Action == resource.ActionCreateVolume || op.Action == resource.ActionDeleteVolume ||
		op.Action == resource.ActionCreateSnapshot || op.Action == resource.ActionDeleteSnapshot
	if volume != s.volumes {
		return nil, toStatus(resource.NotFound(resource.KindOperation, lastSegment(req.GetName())))
	}
	return s.opsSrv.GetOperation(ctx, req)
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
	keyLine   map[string]string
	keySHA1   map[string]string
	opLaunch  map[string]string
	actions   map[string]string
	detach    map[string]map[string]string
	boots     map[string]*storagev1.Volume
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
		keyLine:  map[string]string{},
		keySHA1:  map[string]string{},
		opLaunch: map[string]string{},
		actions:  map[string]string{},
		detach:   map[string]map[string]string{},
		boots:    map[string]*storagev1.Volume{},
	}
}

// rememberDetach stores the detach records of a successful update that
// names "labels". Compute replaces the whole label map on such an update
// (vws-compute grpcapi metadataPatch), so a record the update leaves out is
// gone, as it is on a real instance.
func (w *loopWorld) rememberDetach(id string, labels map[string]string) {
	kept := map[string]string{}
	for key, value := range labels {
		if detachRecordKey(key) {
			kept[key] = value
		}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(kept) == 0 {
		delete(w.detach, id)
		return
	}
	w.detach[id] = kept
}

func (w *loopWorld) detachOf(id string) map[string]string {
	w.mu.Lock()
	defer w.mu.Unlock()
	src := w.detach[id]
	if len(src) == 0 {
		return nil
	}
	out := make(map[string]string, len(src))
	maps.Copy(out, src)
	return out
}

func (w *loopWorld) rememberAction(id, action string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.actions[id] = action
}

func (w *loopWorld) actionOf(id string) string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.actions[id]
}

func (w *loopWorld) putBoot(vol *storagev1.Volume) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.boots[vol.GetName()] = vol
}

func (w *loopWorld) bootsFor(projectID string) []*storagev1.Volume {
	w.mu.Lock()
	defer w.mu.Unlock()
	prefix := "projects/" + projectID + "/"
	var out []*storagev1.Volume
	for name, vol := range w.boots {
		if strings.HasPrefix(name, prefix) {
			out = append(out, vol)
		}
	}
	return out
}

// reuse is the storage idempotency rule for a put. The same request id with
// a different body is a conflict. A new body must use a new request id.
func (w *loopWorld) reuse(requestID, fp string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if requestID == "" {
		return nil
	}
	if prev, ok := w.idem[requestID]; ok && prev != fp {
		return resource.IdempotencyMismatch()
	}
	w.idem[requestID] = fp
	return nil
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
	if op.State == resource.OperationSucceeded && op.Action == resource.ActionDeleteSecurityGroup {
		for _, target := range op.Targets {
			delete(w.groups, target.ID())
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
	keyName := ""
	if ref := spec.GetKeyPair(); ref != "" {
		keyID, err := resource.Parse[resource.KeyPairID](lastSegment(ref))
		if err != nil {
			return nil, toStatus(err)
		}
		keys, err := s.w.set.Compute.DescribeKeyPairs(ctx, backend.Scope{Account: account}, resource.KeyPairQuery{
			IDs: []resource.KeyPairID{keyID}, Page: resource.PageRequest{Size: 1},
		})
		if err != nil {
			return nil, toStatus(err)
		}
		keyName = keys.Items[0].Name
	}
	acc, err := s.w.set.Compute.RunInstances(ctx, backend.Mutation{
		Scope: backend.Scope{Account: account}, Key: req.GetRequestId(), Fingerprint: fp,
	}, resource.RunInstancesRequest{
		ImageID: img, InstanceType: spec.GetMachineType(), SubnetID: subID, Count: 1,
		Tags: userTags(req.GetInstance().GetLabels()), KeyName: keyName, UserData: spec.GetUserData(),
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
	if paths := req.GetUpdateMask().GetPaths(); len(paths) == 1 && paths[0] == "labels" {
		return s.retag(ctx, req)
	}
	spec := req.GetInstance().GetSpec()
	current, err := s.currentVolumes(ctx, req.GetInstance().GetName())
	if err != nil {
		return nil, toStatus(err)
	}
	kind, volName, device := classifyVolumeUpdate(current, spec.GetVolumes())
	switch kind {
	case "attach":
		if bootCount(spec) != 1 {
			return nil, toStatus(resource.Invalid("volumes", "boot required"))
		}
		return s.attachVolume(ctx, req, volName, device)
	case "detach":
		return s.detachVolume(ctx, req, volName, device)
	case "same":
		powerUnset := spec.GetPower() == computev1.InstancePower_INSTANCE_POWER_UNSPECIFIED
		if maskHas(req, "spec.volumes") && bootCount(spec) == 1 && powerUnset {
			// The data volume is already gone. The request id still replays the detach.
			return s.detachVolume(ctx, req, "", "")
		}
	}
	power := spec.GetPower()
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
		resource.ActionTerminateInstances, resource.ActionCreateKeyPair,
		resource.ActionDeleteKeyPair, resource.ActionDeleteSecurityGroup, resource.ActionDeleteSubnet,
		resource.ActionAllocateAddress, resource.ActionReleaseAddress, resource.ActionCreateSnapshot, resource.ActionDeleteSnapshot,
		resource.ActionAssociateAddress, resource.ActionDisassociateAddress,
		resource.ActionModifyVolume, resource.ActionCreateTags, resource.ActionDetachVolume:
		return nil, toStatus(resource.Invalid("power", "unsupported"))
	default:
		return nil, toStatus(resource.Invalid("power", "unsupported"))
	}
	if err != nil {
		return nil, toStatus(err)
	}
	if actionName := req.GetInstance().GetLabels()[labelAction]; actionName != "" {
		s.w.rememberAction(id.String(), actionName)
	}
	s.w.rememberDetach(id.String(), req.GetInstance().GetLabels())
	return runningOp(projectID, acc.Operation, instanceName(projectID, id.String()), commonv1.OperationVerb_OPERATION_VERB_UPDATE, s.w.now)
}

// retag serves a labels-only update as CreateTags with the decoded tags.
func (s *instanceSrv) retag(ctx context.Context, req *computev1.UpdateInstanceRequest) (*longrunningpb.Operation, error) {
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
	tags := userTags(req.GetInstance().GetLabels())
	if len(tags) == 0 {
		return nil, toStatus(resource.Invalid("labels", "no tags"))
	}
	acc, err := s.w.set.Compute.CreateTags(ctx, backend.Mutation{
		Scope: backend.Scope{Account: account}, Key: req.GetRequestId(), Fingerprint: fp,
	}, resource.CreateTagsRequest{IDs: []resource.InstanceID{id}, Tags: tags})
	if err != nil {
		return nil, toStatus(err)
	}
	if actionName := req.GetInstance().GetLabels()[labelAction]; actionName != "" {
		s.w.rememberAction(id.String(), actionName)
	}
	s.w.rememberDetach(id.String(), req.GetInstance().GetLabels())
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
	s.w.rememberDetach(instID.String(), req.GetInstance().GetLabels())
	return runningOp(projectID, acc.Operation, volumeName(projectID, acc.Items[0].ID.String()), commonv1.OperationVerb_OPERATION_VERB_UPDATE, s.w.now)
}

func (s *instanceSrv) detachVolume(
	ctx context.Context, req *computev1.UpdateInstanceRequest, volName, device string,
) (*longrunningpb.Operation, error) {
	projectID, err := projectOfName(req.GetInstance().GetName())
	if err != nil {
		return nil, toStatus(err)
	}
	account, err := accountOf(projectID)
	if err != nil {
		return nil, toStatus(err)
	}
	instID, err := resource.Parse[resource.InstanceID](lastSegment(req.GetInstance().GetName()))
	if err != nil {
		return nil, toStatus(err)
	}
	var volID resource.VolumeID
	if volName != "" {
		volID, err = resource.Parse[resource.VolumeID](lastSegment(volName))
		if err != nil {
			return nil, toStatus(err)
		}
	}
	fp, err := protoFingerprint(req)
	if err != nil {
		return nil, toStatus(err)
	}
	acc, err := s.w.set.Compute.DetachVolume(ctx, backend.Mutation{
		Scope: backend.Scope{Account: account}, Key: req.GetRequestId(), Fingerprint: fp,
	}, resource.DetachVolumeRequest{VolumeID: volID, InstanceID: instID, Device: device})
	if err != nil {
		// The operation id is written after the drop, as a second update whose
		// volume list no longer changes. The fake has no volume id to detach.
		if volName == "" && resource.CodeOf(err) == resource.CodeNotFound {
			s.w.rememberDetach(instID.String(), req.GetInstance().GetLabels())
			msg, opErr := runningNamed(
				projectID, req.GetRequestId(), instanceName(projectID, instID.String()),
				commonv1.OperationVerb_OPERATION_VERB_UPDATE, s.w.now,
			)
			if opErr != nil {
				return nil, opErr
			}
			msg.Done = true
			return msg, nil
		}
		return nil, toStatus(err)
	}
	s.w.rememberDetach(instID.String(), req.GetInstance().GetLabels())
	s.w.rememberAction(instID.String(), resource.ActionDetachVolume.String())
	return runningOp(
		projectID, acc.Operation, instanceName(projectID, instID.String()),
		commonv1.OperationVerb_OPERATION_VERB_UPDATE, s.w.now,
	)
}

func (s *instanceSrv) currentVolumes(ctx context.Context, name string) ([]*computev1.VolumeAttachment, error) {
	projectID, err := projectOfName(name)
	if err != nil {
		return nil, err
	}
	account, err := accountOf(projectID)
	if err != nil {
		return nil, err
	}
	id, err := resource.Parse[resource.InstanceID](lastSegment(name))
	if err != nil {
		return nil, err
	}
	page, err := s.w.set.Compute.DescribeInstances(ctx, backend.Scope{Account: account}, resource.InstanceQuery{
		IDs: []resource.InstanceID{id}, Page: resource.PageRequest{Size: 1},
	})
	if err != nil {
		return nil, err
	}
	if len(page.Items) == 0 {
		return nil, resource.NotFound(resource.KindInstance, id.String())
	}
	return volumeAttachments(projectID, page.Items[0].BlockDevices), nil
}

func classifyVolumeUpdate(current, next []*computev1.VolumeAttachment) (kind, volName, device string) {
	cur := map[string]*computev1.VolumeAttachment{}
	nxt := map[string]*computev1.VolumeAttachment{}
	for _, v := range current {
		if v.GetVolume() != "" {
			cur[v.GetVolume()] = v
		}
	}
	for _, v := range next {
		if v.GetVolume() != "" {
			nxt[v.GetVolume()] = v
		}
	}
	var added, removed []*computev1.VolumeAttachment
	for name, v := range nxt {
		if _, ok := cur[name]; !ok {
			added = append(added, v)
		}
	}
	for name, v := range cur {
		if _, ok := nxt[name]; !ok {
			removed = append(removed, v)
		}
	}
	if len(added) == 1 && len(removed) == 0 && !bootAttachment(added[0]) {
		return "attach", added[0].GetVolume(), added[0].GetDeviceName()
	}
	if len(removed) == 1 && len(added) == 0 && !bootAttachment(removed[0]) {
		return "detach", removed[0].GetVolume(), removed[0].GetDeviceName()
	}
	if len(added) == 0 && len(removed) == 0 {
		return "same", "", ""
	}
	return "other", "", ""
}

func bootAttachment(v *computev1.VolumeAttachment) bool {
	return v.GetBoot() || v.GetDeviceName() == "boot" || v.GetDeviceName() == resource.RootDeviceName
}

func maskHas(req *computev1.UpdateInstanceRequest, path string) bool {
	for _, got := range req.GetUpdateMask().GetPaths() {
		if got == path {
			return true
		}
	}
	return false
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

func bootCount(spec *computev1.InstanceSpec) int {
	n := 0
	for _, vol := range spec.GetVolumes() {
		if vol.GetBoot() || vol.GetDeviceName() == "boot" {
			n++
		}
	}
	return n
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
		inst := snap.inst
		page, rowErr := s.w.set.Compute.DescribeInstances(ctx, backend.Scope{Account: account}, resource.InstanceQuery{
			IDs: []resource.InstanceID{snap.inst.ID}, Page: resource.PageRequest{Size: 1},
		})
		if rowErr == nil && len(page.Items) == 1 {
			// The launch snapshot is taken before a later attach.
			inst.BlockDevices = page.Items[0].BlockDevices
			inst.RootDeviceName = page.Items[0].RootDeviceName
		}
		return s.stampAction(instanceProto(inst, projectID, snap.vpc), inst.ID.String()), nil
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
	return s.stampAction(instanceProto(inst, projectID, s.w.vpcOf(inst.SubnetID.String())), inst.ID.String()), nil
}

func (s *instanceSrv) stampAction(msg *computev1.Instance, id string) *computev1.Instance {
	action := s.w.actionOf(id)
	records := s.w.detachOf(id)
	if action == "" && len(records) == 0 {
		return msg
	}
	if msg.Labels == nil {
		msg.Labels = map[string]string{}
	}
	if action != "" {
		msg.Labels[labelAction] = action
	}
	maps.Copy(msg.Labels, records)
	return msg
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
		msg := instanceProto(inst, projectID, s.w.vpcOf(inst.SubnetID.String()))
		items = append(items, s.stampAction(msg, inst.ID.String()))
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
	if spec.GetImage() != "" {
		name := volumeName(projectID, req.GetVolumeId())
		fp, err := protoFingerprint(req)
		if err != nil {
			return nil, toStatus(err)
		}
		if err := s.w.admit(req.GetRequestId(), fp, name); err != nil {
			return nil, toStatus(err)
		}
		s.w.putBoot(&storagev1.Volume{
			Name: name,
			Spec: proto.Clone(spec).(*storagev1.VolumeSpec),
			Status: &storagev1.VolumeStatus{Observed: &commonv1.ObservedState{
				State: commonv1.ReconciliationState_RECONCILIATION_STATE_READY,
			}},
		})
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
	var snap resource.SnapshotID
	if name := spec.GetSnapshot(); name != "" {
		_, _, snap, err = snapshotRef(name)
		if err != nil {
			return nil, toStatus(err)
		}
	}
	acc, err := s.w.set.Compute.CreateVolume(ctx, backend.Mutation{
		Scope: backend.Scope{Account: account}, Key: req.GetRequestId(), Fingerprint: fp,
	}, resource.CreateVolumeRequest{SizeGiB: spec.GetSizeGib(), Zone: resource.ZoneName, SnapshotID: snap})
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
		}, resource.CreateVpcRequest{Cidr: req.GetVpc().GetSpec().GetIpv4Cidr(), Tags: userTags(req.GetVpc().GetLabels())})
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
	}, resource.CreateSubnetRequest{Cidr: req.GetSubnet().GetSpec().GetIpv4Cidr(), VpcID: vpcRef, Tags: userTags(req.GetSubnet().GetLabels())})
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

// bucketSrv answers CreateBucket and DeleteBucket as vws-storage does
// (#315): a request id it has seen returns that request's operation
// (storage.Service.Submit), and
// a create for a bucket the project already holds returns a succeeded
// operation for that bucket (vws-proto operation.proto, Create). Unlike
// vws-storage, names stay global as in the fake, so another project's name
// is ALREADY_EXISTS here.
type bucketSrv struct {
	storagev1.UnimplementedBucketServiceServer
	w   *loopWorld
	mu  sync.Mutex
	ops map[string]*longrunningpb.Operation
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
	s.mu.Lock()
	defer s.mu.Unlock()
	token := projectID + "/" + req.GetRequestId()
	if op, ok := s.ops[token]; ok {
		return op, nil
	}
	scope := backend.Scope{Account: account}
	bucket, err := s.w.set.Storage.GetBucket(ctx, scope, name)
	if resource.CodeOf(err) == resource.CodeNotFound {
		bucket, err = s.w.set.Storage.CreateBucket(ctx, scope, name)
	}
	if err != nil {
		return nil, toStatus(err)
	}
	resName := bucketName(projectID, name.String())
	op, err := doneResource(projectID, req.GetRequestId(), resName, bucketProto(bucket, projectID), s.w.now)
	if err != nil {
		return nil, err
	}
	if s.ops == nil {
		s.ops = map[string]*longrunningpb.Operation{}
	}
	s.ops[token] = op
	return op, nil
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
	s.mu.Lock()
	defer s.mu.Unlock()
	token := projectID + "/" + req.GetRequestId()
	if op, ok := s.ops[token]; ok {
		return op, nil
	}
	if err := s.w.set.Storage.DeleteBucket(ctx, backend.Scope{Account: account}, name); err != nil {
		return nil, toStatus(err)
	}
	gone := bucketProto(resource.Bucket{Name: name, OwnerID: account}, projectID)
	op, err := doneResource(projectID, req.GetRequestId(), req.GetName(), gone, s.w.now)
	if err != nil {
		return nil, err
	}
	if s.ops == nil {
		s.ops = map[string]*longrunningpb.Operation{}
	}
	s.ops[token] = op
	return op, nil
}

type objectSrv struct {
	storagev1.UnimplementedObjectServiceServer
	w *loopWorld
}

func (s *objectSrv) ListObjects(ctx context.Context, req *storagev1.ListObjectsRequest) (*storagev1.ListObjectsResponse, error) {
	projectID, account, bucket, err := bucketRef(req.GetParent())
	if err != nil {
		return nil, toStatus(err)
	}
	size := int(req.GetPageSize())
	if size <= 0 {
		size = 50
	}
	if size > 1000 {
		size = 1000
	}
	// Two keys per page forces the client to follow the service token.
	if size > 2 {
		size = 2
	}
	// The RPC has no delimiter. An empty delimiter keeps every key as an object
	// so the client can group after it has read every page.
	listing, err := s.w.set.Storage.ListObjects(ctx, backend.Scope{Account: account}, resource.ObjectQuery{
		Bucket: bucket, MaxKeys: size, Token: req.GetPageToken(),
	})
	if err != nil {
		return nil, toStatus(err)
	}
	items := make([]*storagev1.Object, 0, len(listing.Objects))
	for _, obj := range listing.Objects {
		items = append(items, objectProto(obj, projectID))
	}
	return &storagev1.ListObjectsResponse{Objects: items, NextPageToken: listing.NextToken}, nil
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

func (s *objectSrv) ReadObject(ctx context.Context, req *storagev1.ReadObjectRequest) (*storagev1.ReadObjectResponse, error) {
	projectID, account, bucket, key, err := objectRef(req.GetName())
	if err != nil {
		return nil, toStatus(err)
	}
	obj, rc, err := s.w.set.Storage.GetObject(ctx, backend.Scope{Account: account}, resource.GetObjectRequest{Bucket: bucket, Key: key})
	if err != nil {
		return nil, toStatus(err)
	}
	defer func() { _ = rc.Close() }()
	body, err := io.ReadAll(rc)
	if err != nil {
		return nil, toStatus(resource.Internal(err))
	}
	return &storagev1.ReadObjectResponse{Contents: body, Object: objectProto(obj, projectID)}, nil
}

// CreateObject keeps the vws-storage rule: an existing object with the same
// bytes is accepted as a create, and different bytes are ALREADY_EXISTS.
func (s *objectSrv) CreateObject(ctx context.Context, req *storagev1.CreateObjectRequest) (*longrunningpb.Operation, error) {
	name := req.GetParent() + "/objects/" + req.GetObjectId()
	projectID, account, bucket, key, err := objectRef(name)
	if err != nil {
		return nil, toStatus(err)
	}
	scope := backend.Scope{Account: account}
	if obj, rc, err := s.w.set.Storage.GetObject(ctx, scope, resource.GetObjectRequest{Bucket: bucket, Key: key}); err == nil {
		stored, readErr := io.ReadAll(rc)
		_ = rc.Close()
		if readErr != nil {
			return nil, toStatus(resource.Internal(readErr))
		}
		if !bytes.Equal(stored, req.GetContents()) {
			return nil, toStatus(resource.AlreadyExists(resource.KindUnspecified, name))
		}
		return doneResource(projectID, req.GetRequestId(), name, objectProto(obj, projectID), s.w.now)
	}
	obj, err := s.w.set.Storage.PutObject(ctx, scope, resource.PutObjectRequest{
		Bucket: bucket, Key: key, ContentType: req.GetObject().GetSpec().GetContentType(), Size: int64(len(req.GetContents())),
	}, bytes.NewReader(req.GetContents()))
	if err != nil {
		return nil, toStatus(err)
	}
	return doneResource(projectID, req.GetRequestId(), name, objectProto(obj, projectID), s.w.now)
}

func (s *objectSrv) UpdateObject(ctx context.Context, req *storagev1.UpdateObjectRequest) (*longrunningpb.Operation, error) {
	if !objectMaskMatches(req.GetUpdateMask()) {
		return nil, toStatus(resource.Unimplemented("object field mask"))
	}
	sum := sha256.Sum256(req.GetContents())
	if err := s.w.reuse(req.GetRequestId(), hex.EncodeToString(sum[:])); err != nil {
		return nil, toStatus(err)
	}
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
	verb := operationVerb(op.Action)
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
		return nil, toStatus(resource.Internal(errors.New("bad operation state")))
	}
	return msg, nil
}

func operationVerb(action resource.Action) commonv1.OperationVerb {
	switch action {
	case resource.ActionStopInstances, resource.ActionStartInstances, resource.ActionAttachVolume,
		resource.ActionAuthorizeSecurityGroupIngress, resource.ActionAssociateAddress,
		resource.ActionDisassociateAddress, resource.ActionModifyVolume,
		resource.ActionCreateTags, resource.ActionDetachVolume:
		return commonv1.OperationVerb_OPERATION_VERB_UPDATE
	case resource.ActionTerminateInstances, resource.ActionDeleteVpc, resource.ActionDeleteVolume, resource.ActionDeleteKeyPair, resource.ActionDeleteSecurityGroup, resource.ActionDeleteSubnet, resource.ActionReleaseAddress, resource.ActionDeleteSnapshot:
		return commonv1.OperationVerb_OPERATION_VERB_DELETE
	case resource.ActionRunInstances, resource.ActionCreateSubnet, resource.ActionCreateVpc, resource.ActionCreateVolume, resource.ActionCreateSecurityGroup, resource.ActionCreateKeyPair, resource.ActionAllocateAddress, resource.ActionCreateSnapshot:
		return commonv1.OperationVerb_OPERATION_VERB_CREATE
	default:
		return commonv1.OperationVerb_OPERATION_VERB_UNSPECIFIED
	}
}

func runningOp(projectID string, op resource.Operation, resourceName string, verb commonv1.OperationVerb, now time.Time) (*longrunningpb.Operation, error) {
	msg, err := longOp(projectID, op.ID.Local(), resourceName, op.ID.Local(), verb, now)
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
	case resource.KindAddress:
		return addressName(projectID, ref.ID())
	case resource.KindSnapshot:
		return snapshotName(projectID, ref.ID())
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
		return "", resource.AccountID{}, resource.BucketName{}, resource.Internal(errors.New("bad bucket name"))
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
		return "", resource.AccountID{}, resource.BucketName{}, resource.ObjectKey{}, resource.Internal(errors.New("bad object name"))
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
