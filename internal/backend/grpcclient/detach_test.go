package grpcclient

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	longrunningpb "cloud.google.com/go/longrunning/autogen/longrunningpb"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	commonv1 "github.com/popododo0720/vws-proto/gen/go/vws/common/v1"
	computev1 "github.com/popododo0720/vws-proto/gen/go/vws/compute/v1"
	storagev1 "github.com/popododo0720/vws-proto/gen/go/vws/storage/v1"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// detachWorld is a compute service that stores label replaces and completes
// an update immediately when the volume list does not change.
type detachWorld struct {
	computev1.UnimplementedInstanceServiceServer
	storagev1.UnimplementedVolumeServiceServer
	mu          sync.Mutex
	inst        []*computev1.Instance
	vol         *storagev1.Volume
	more        []*storagev1.Volume
	byRequest   map[string]*detachRecord
	updates     int
	nextOp      int
	etagN       int
	pages       []*computev1.Instance
	repeatToken bool
	gate        *detachGate
	// failSameSpec fails that many updates that leave the volume list as it
	// is, such as the write that saves a detach's operation id.
	failSameSpec int
	// beforeWrite runs once, under the lock, before the next update is
	// checked. A test uses it to land a concurrent write first.
	beforeWrite func(inst *computev1.Instance)
	// maxLabels, when set, rejects an update with more labels, or a label
	// longer than 63 bytes, as vws-compute does (internal/compute/metadata.go).
	maxLabels int
}

// detachRecord is the idempotency record for one UpdateInstance request id.
type detachRecord struct {
	fp string
	op *longrunningpb.Operation
}

// detachGate holds both instance reads until each has copied the spec, then lets writes run.
type detachGate struct {
	mu       sync.Mutex
	entered  int
	finished int
	release  chan struct{}
	writes   chan struct{}
	onceR    sync.Once
	onceW    sync.Once
}

func (s *detachWorld) GetVolume(_ context.Context, req *storagev1.GetVolumeRequest) (*storagev1.Volume, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.vol != nil && s.vol.GetName() == req.GetName() {
		return s.vol, nil
	}
	for _, vol := range s.more {
		if vol.GetName() == req.GetName() {
			return vol, nil
		}
	}
	return nil, status.Error(codes.NotFound, "missing volume")
}

func (s *detachWorld) ListInstances(
	_ context.Context, req *computev1.ListInstancesRequest,
) (*computev1.ListInstancesResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.repeatToken {
		item := s.inst
		if len(s.pages) > 0 {
			item = s.pages[:1]
		}
		return &computev1.ListInstancesResponse{Instances: item, NextPageToken: "loop"}, nil
	}
	if s.pages == nil {
		return &computev1.ListInstancesResponse{Instances: s.inst}, nil
	}
	index := 0
	if req.GetPageToken() != "" {
		n, err := strconv.Atoi(req.GetPageToken())
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, "bad page token")
		}
		index = n
	}
	if index >= len(s.pages) {
		return &computev1.ListInstancesResponse{}, nil
	}
	next := ""
	if index+1 < len(s.pages) {
		next = strconv.Itoa(index + 1)
	}
	return &computev1.ListInstancesResponse{
		Instances: []*computev1.Instance{s.pages[index]}, NextPageToken: next,
	}, nil
}

func (s *detachWorld) GetInstance(ctx context.Context, req *computev1.GetInstanceRequest) (*computev1.Instance, error) {
	if s.gate != nil {
		if err := s.gate.begin(ctx); err != nil {
			return nil, err
		}
	}
	s.mu.Lock()
	var found *computev1.Instance
	for _, inst := range s.inst {
		if inst.GetName() == req.GetName() {
			found = proto.Clone(inst).(*computev1.Instance)
			break
		}
	}
	s.mu.Unlock()
	if s.gate != nil {
		s.gate.finish()
	}
	if found == nil {
		return nil, status.Error(codes.NotFound, "missing instance")
	}
	return found, nil
}

func (s *detachWorld) UpdateInstance(
	ctx context.Context, req *computev1.UpdateInstanceRequest,
) (*longrunningpb.Operation, error) {
	if s.gate != nil {
		if err := s.gate.beforeWrite(ctx); err != nil {
			return nil, err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	fp, err := detachReqFingerprint(req)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	if rec, ok := s.byRequest[req.GetRequestId()]; ok {
		if rec.fp != fp {
			return nil, vwsStatus(codes.Aborted, "IDEMPOTENCY_CONFLICT", "fingerprint mismatch")
		}
		return rec.op, nil
	}
	var inst *computev1.Instance
	for _, item := range s.inst {
		if item.GetName() == req.GetInstance().GetName() {
			inst = item
			break
		}
	}
	if inst == nil {
		return nil, status.Error(codes.NotFound, "missing instance")
	}
	if hook := s.beforeWrite; hook != nil {
		s.beforeWrite = nil
		hook(inst)
		s.etagN++
		inst.Etag = strconv.Itoa(s.etagN)
	}
	// An empty etag is no precondition, as in vws-compute checkEtag.
	if etag := req.GetInstance().GetEtag(); etag != "" && etag != inst.GetEtag() {
		return nil, vwsStatus(codes.Aborted, "ETAG_MISMATCH", "etag mismatch")
	}
	if s.maxLabels > 0 {
		if n := len(req.GetInstance().GetLabels()); n > s.maxLabels {
			return nil, status.Errorf(codes.InvalidArgument, "%d labels, at most %d", n, s.maxLabels)
		}
		for k, v := range req.GetInstance().GetLabels() {
			if len(k) > 63 || len(v) > 63 {
				return nil, status.Errorf(codes.InvalidArgument, "label %q is over 63 bytes", k)
			}
		}
	}
	removed := removedDetachDevice(inst.GetSpec().GetVolumes(), req.GetInstance().GetSpec().GetVolumes())
	if s.failSameSpec > 0 && len(inst.GetSpec().GetVolumes()) == len(req.GetInstance().GetSpec().GetVolumes()) {
		s.failSameSpec--
		return nil, status.Error(codes.Unavailable, "compute restarted")
	}
	inst.Labels = req.GetInstance().GetLabels()
	if inst.Spec == nil {
		inst.Spec = &computev1.InstanceSpec{}
	}
	if maskHas(req, "spec.volumes") {
		inst.Spec.Volumes = req.GetInstance().GetSpec().GetVolumes()
	}
	s.etagN++
	inst.Etag = strconv.Itoa(s.etagN)
	s.updates++
	s.nextOp++
	op, err := longOp(
		projectOfInstance(inst.GetName()), fmt.Sprintf("%016x", s.nextOp), inst.GetName(),
		req.GetRequestId(), commonv1.OperationVerb_OPERATION_VERB_UPDATE, time.Now().UTC(),
	)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	if removed == "" {
		op.Done = true
	}
	s.byRequest[req.GetRequestId()] = &detachRecord{fp: fp, op: op}
	return op, nil
}

func (g *detachGate) begin(ctx context.Context) error {
	g.mu.Lock()
	if g.finished >= 2 {
		g.mu.Unlock()
		return nil
	}
	g.entered++
	n := g.entered
	g.mu.Unlock()
	if n >= 2 {
		g.onceR.Do(func() { close(g.release) })
	}
	select {
	case <-g.release:
		return nil
	case <-ctx.Done():
		return status.FromContextError(ctx.Err()).Err()
	}
}

func (g *detachGate) finish() {
	g.mu.Lock()
	if g.finished >= 2 {
		g.mu.Unlock()
		return
	}
	g.finished++
	n := g.finished
	g.mu.Unlock()
	if n >= 2 {
		g.onceW.Do(func() { close(g.writes) })
	}
}

func (g *detachGate) beforeWrite(ctx context.Context) error {
	select {
	case <-g.writes:
		return nil
	case <-ctx.Done():
		return status.FromContextError(ctx.Err()).Err()
	}
}

func (s *detachWorld) finishAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, rec := range s.byRequest {
		rec.op.Done = true
	}
}

func detachReqFingerprint(req *computev1.UpdateInstanceRequest) (string, error) {
	cloned := proto.Clone(req).(*computev1.UpdateInstanceRequest)
	if cloned.GetInstance() != nil {
		cloned.Instance.Etag = ""
	}
	return protoFingerprint(cloned)
}

func removedDetachDevice(before, after []*computev1.VolumeAttachment) string {
	kept := map[string]struct{}{}
	for _, vol := range after {
		kept[vol.GetVolume()] = struct{}{}
	}
	for _, vol := range before {
		if _, ok := kept[vol.GetVolume()]; ok || vol.GetBoot() || vol.GetDeviceName() == "boot" {
			continue
		}
		return vol.GetDeviceName()
	}
	return ""
}

func vwsStatus(code codes.Code, reason, msg string) error {
	st, err := status.New(code, msg).WithDetails(&errdetails.ErrorInfo{Reason: reason, Domain: "vws.dev"})
	if err != nil {
		return status.Error(code, msg)
	}
	return st.Err()
}

func projectOfInstance(name string) string {
	projectID, err := projectOfName(name)
	if err != nil {
		return ""
	}
	return projectID
}

func dialDetachWorld(t *testing.T, world *detachWorld) computeClient {
	t.Helper()
	// vws-compute always returns an etag, so every instance starts with one.
	world.mu.Lock()
	for _, inst := range append(append([]*computev1.Instance(nil), world.inst...), world.pages...) {
		if inst.GetEtag() == "" {
			world.etagN++
			inst.Etag = strconv.Itoa(world.etagN)
		}
	}
	world.mu.Unlock()
	lis := bufconn.Listen(MaxMessageBytes())
	srv := grpc.NewServer()
	computev1.RegisterInstanceServiceServer(srv, world)
	storagev1.RegisterVolumeServiceServer(srv, world)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///detach",
		append(dialOptions(), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}))...,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return computeClient{&api{
		instances: computev1.NewInstanceServiceClient(conn),
		volumes:   storagev1.NewVolumeServiceClient(conn),
	}}
}

func TestDetachKeepsLabelsAndReadsTheSpec(t *testing.T) {
	account := mustAccount(t)
	projectID := project(account)
	const (
		instID  = "i-0123456789abcdef0"
		otherID = "i-0fedcba9876543210"
		rootID  = "vol-0123456789abcdef0"
		dataID  = "vol-0fedcba9876543210"
	)
	holder := observedInstance(projectID, instID,
		commonv1.ReconciliationState_RECONCILIATION_STATE_READY,
		computev1.InstancePower_INSTANCE_POWER_RUNNING)
	holder.Labels[labelLaunch] = "launch-1"
	holder.Labels["env"] = "dev"
	holder.Spec.Volumes = []*computev1.VolumeAttachment{
		{Volume: volumeName(projectID, rootID), DeviceName: "boot", Boot: true},
		{Volume: volumeName(projectID, dataID), DeviceName: "/dev/sdf"},
	}
	other := observedInstance(projectID, otherID,
		commonv1.ReconciliationState_RECONCILIATION_STATE_READY,
		computev1.InstancePower_INSTANCE_POWER_RUNNING)
	other.Spec.Volumes = []*computev1.VolumeAttachment{
		{Volume: volumeName(projectID, "vol-0abcdef0123456789"), DeviceName: "boot", Boot: true},
	}
	world := &detachWorld{
		inst:      []*computev1.Instance{holder, other},
		vol:       observedVolume(projectID, dataID, commonv1.ReconciliationState_RECONCILIATION_STATE_READY, ""),
		byRequest: map[string]*detachRecord{},
	}
	client := dialDetachWorld(t, world)
	ctx := context.Background()
	scope := backend.Scope{Account: account}
	data, err := resource.Parse[resource.VolumeID](dataID)
	if err != nil {
		t.Fatal(err)
	}
	holderID, err := resource.Parse[resource.InstanceID](instID)
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := resource.Parse[resource.InstanceID](otherID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.DetachVolume(ctx, backend.Mutation{
		Scope: scope, Key: "k-wrong", Fingerprint: "fp-wrong",
	}, resource.DetachVolumeRequest{
		VolumeID: data, InstanceID: wrong, Device: "/dev/sdf",
	})
	if !resource.IsAttachmentNotFound(resource.AsError(err)) {
		t.Fatalf("wrong instance: %v", err)
	}
	if world.updateCount() != 0 {
		t.Fatalf("wrong instance wrote %d updates", world.updateCount())
	}

	mut := backend.Mutation{Scope: scope, Key: "k-detach", Fingerprint: "fp-detach"}
	detached, err := client.DetachVolume(ctx, mut, resource.DetachVolumeRequest{VolumeID: data})
	if err != nil {
		t.Fatal(err)
	}
	item := detached.Items[0]
	if item.Status != resource.AttachmentDetaching || item.InstanceID != holderID || item.Device != "/dev/sdf" {
		t.Fatalf("detach %+v", item)
	}
	if detached.Operation.Action != resource.ActionDetachVolume {
		t.Fatalf("action %s", detached.Operation.Action)
	}
	assertDetachLabels(t, world.labelsOf(instanceName(projectID, instID)))
	vols := world.volumeNames(instanceName(projectID, instID))
	if len(vols) != 1 || vols[0] != volumeName(projectID, rootID) {
		t.Fatalf("volumes after detach %v", vols)
	}

	wrote := world.updateCount()
	replayed, err := client.DetachVolume(ctx, mut, resource.DetachVolumeRequest{
		VolumeID: data, InstanceID: holderID, Device: "/dev/sdf",
	})
	if err != nil || replayed.Operation.ID != detached.Operation.ID {
		t.Fatalf("replay %v %+v", err, replayed)
	}
	if world.updateCount() != wrote {
		t.Fatalf("replay wrote a second update (%d)", world.updateCount())
	}

	_, err = client.DetachVolume(ctx, backend.Mutation{
		Scope: scope, Key: "k-again", Fingerprint: "fp-again",
	}, resource.DetachVolumeRequest{
		VolumeID: data, InstanceID: holderID, Device: "/dev/sdf",
	})
	if resource.CodeOf(err) != resource.CodeConflict {
		t.Fatalf("second detach: %v", err)
	}
	assertDetachLabels(t, world.labelsOf(instanceName(projectID, instID)))
}

func (s *detachWorld) updateCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.updates
}

func (s *detachWorld) labelsOf(name string) map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, inst := range s.inst {
		if inst.GetName() == name {
			return inst.GetLabels()
		}
	}
	return nil
}

func (s *detachWorld) volumeNames(name string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, inst := range s.inst {
		if inst.GetName() != name {
			continue
		}
		out := make([]string, 0, len(inst.GetSpec().GetVolumes()))
		for _, v := range inst.GetSpec().GetVolumes() {
			out = append(out, v.GetVolume())
		}
		return out
	}
	return nil
}

func TestStoppedRootDetachStaysOnTheSpec(t *testing.T) {
	account := mustAccount(t)
	projectID := project(account)
	const (
		instID = "i-0123456789abcdef0"
		rootID = "vol-0123456789abcdef0"
	)
	holder := observedInstance(projectID, instID,
		commonv1.ReconciliationState_RECONCILIATION_STATE_READY,
		computev1.InstancePower_INSTANCE_POWER_STOPPED)
	holder.Spec.Volumes = []*computev1.VolumeAttachment{
		{Volume: volumeName(projectID, rootID), DeviceName: "boot", Boot: true},
	}
	world := &detachWorld{
		inst:      []*computev1.Instance{holder},
		vol:       observedVolume(projectID, rootID, commonv1.ReconciliationState_RECONCILIATION_STATE_READY, instID),
		byRequest: map[string]*detachRecord{},
	}
	client := dialDetachWorld(t, world)
	root, err := resource.Parse[resource.VolumeID](rootID)
	if err != nil {
		t.Fatal(err)
	}
	holderID, err := resource.Parse[resource.InstanceID](instID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.DetachVolume(context.Background(), backend.Mutation{
		Scope: backend.Scope{Account: account}, Key: "k-root", Fingerprint: "fp-root",
	}, resource.DetachVolumeRequest{VolumeID: root, InstanceID: holderID})
	if resource.CodeOf(err) != resource.CodeConflict {
		t.Fatalf("stopped root: %v", err)
	}
	vols := world.volumeNames(instanceName(projectID, instID))
	if len(vols) != 1 || vols[0] != volumeName(projectID, rootID) || world.updateCount() != 0 {
		t.Fatalf("root spec %v updates %d", vols, world.updateCount())
	}
}

func TestDetachReplayAfterCompletionKeepsTheDevice(t *testing.T) {
	account := mustAccount(t)
	projectID := project(account)
	const (
		instID = "i-0123456789abcdef0"
		rootID = "vol-0123456789abcdef0"
		dataID = "vol-0fedcba9876543210"
	)
	holder := observedInstance(projectID, instID,
		commonv1.ReconciliationState_RECONCILIATION_STATE_READY,
		computev1.InstancePower_INSTANCE_POWER_RUNNING)
	launched := time.Unix(1_700_000_100, 0).UTC()
	created := time.Unix(1_700_000_000, 0).UTC()
	holder.CreateTime = timestamppb.New(launched)
	holder.Spec.Volumes = []*computev1.VolumeAttachment{
		{Volume: volumeName(projectID, rootID), DeviceName: "boot", Boot: true},
		{Volume: volumeName(projectID, dataID), DeviceName: "/dev/sdf"},
	}
	dataVol := observedVolume(projectID, dataID, commonv1.ReconciliationState_RECONCILIATION_STATE_READY, instID)
	dataVol.CreateTime = timestamppb.New(created)
	dataVol.Status.DeviceName = "/dev/sdf"
	world := &detachWorld{
		inst:      []*computev1.Instance{holder},
		vol:       dataVol,
		byRequest: map[string]*detachRecord{},
	}
	client := dialDetachWorld(t, world)
	ctx := context.Background()
	scope := backend.Scope{Account: account}
	data, err := resource.Parse[resource.VolumeID](dataID)
	if err != nil {
		t.Fatal(err)
	}
	holderID, err := resource.Parse[resource.InstanceID](instID)
	if err != nil {
		t.Fatal(err)
	}
	mut := backend.Mutation{Scope: scope, Key: "k-replay", Fingerprint: "fp-replay"}
	first, err := client.DetachVolume(ctx, mut, resource.DetachVolumeRequest{
		VolumeID: data, InstanceID: holderID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.Items[0].Device != "/dev/sdf" || first.Items[0].Status != resource.AttachmentDetaching {
		t.Fatalf("first %+v", first.Items[0])
	}
	if !first.Items[0].AttachTime.Equal(launched) || first.Items[0].AttachTime.Equal(created) {
		t.Fatalf("attachTime %s, volume created %s, instance launched %s",
			first.Items[0].AttachTime, created, launched)
	}
	world.finishAll()
	again, err := client.DetachVolume(ctx, mut, resource.DetachVolumeRequest{VolumeID: data})
	if err != nil {
		t.Fatalf("completed replay: %v", err)
	}
	if again.Operation.ID != first.Operation.ID || again.Items[0].Device != "/dev/sdf" ||
		again.Items[0].Status != resource.AttachmentDetaching {
		t.Fatalf("replay %+v op %s", again.Items[0], again.Operation.ID)
	}
	_, err = client.DetachVolume(ctx, backend.Mutation{
		Scope: scope, Key: "k-replay", Fingerprint: "fp-other",
	}, resource.DetachVolumeRequest{VolumeID: data, InstanceID: holderID})
	if resource.CodeOf(err) != resource.CodeIdempotencyMismatch {
		t.Fatalf("fresh fingerprint: %v", err)
	}
	_, err = client.DetachVolume(ctx, backend.Mutation{
		Scope: scope, Key: "k-fresh", Fingerprint: "fp-fresh",
	}, resource.DetachVolumeRequest{VolumeID: data, InstanceID: holderID})
	if resource.CodeOf(err) != resource.CodeConflict {
		t.Fatalf("fresh client: %v", err)
	}
}

func TestConcurrentDetachKeepsBothVolumesOff(t *testing.T) {
	account := mustAccount(t)
	projectID := project(account)
	const (
		instID  = "i-0123456789abcdef0"
		rootID  = "vol-0123456789abcdef0"
		leftID  = "vol-0fedcba9876543210"
		rightID = "vol-0abcdef0123456789"
	)
	holder := observedInstance(projectID, instID,
		commonv1.ReconciliationState_RECONCILIATION_STATE_READY,
		computev1.InstancePower_INSTANCE_POWER_RUNNING)
	holder.Spec.Volumes = []*computev1.VolumeAttachment{
		{Volume: volumeName(projectID, rootID), DeviceName: "boot", Boot: true},
		{Volume: volumeName(projectID, leftID), DeviceName: "/dev/sdf"},
		{Volume: volumeName(projectID, rightID), DeviceName: "/dev/sdg"},
	}
	world := &detachWorld{
		inst: []*computev1.Instance{holder},
		vol:  observedVolume(projectID, leftID, commonv1.ReconciliationState_RECONCILIATION_STATE_READY, instID),
		more: []*storagev1.Volume{
			observedVolume(projectID, rightID, commonv1.ReconciliationState_RECONCILIATION_STATE_READY, instID),
		},
		byRequest: map[string]*detachRecord{},
		gate: &detachGate{
			release: make(chan struct{}),
			writes:  make(chan struct{}),
		},
	}
	client := dialDetachWorld(t, world)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	scope := backend.Scope{Account: account}
	left, err := resource.Parse[resource.VolumeID](leftID)
	if err != nil {
		t.Fatal(err)
	}
	right, err := resource.Parse[resource.VolumeID](rightID)
	if err != nil {
		t.Fatal(err)
	}
	holderID, err := resource.Parse[resource.InstanceID](instID)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errCh := make(chan error, 2)
	for _, item := range []struct {
		id     resource.VolumeID
		key    string
		device string
	}{
		{left, "k-left", "/dev/sdf"},
		{right, "k-right", "/dev/sdg"},
	} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			acc, callErr := client.DetachVolume(ctx, backend.Mutation{
				Scope: scope, Key: item.key, Fingerprint: item.key,
			}, resource.DetachVolumeRequest{VolumeID: item.id, InstanceID: holderID, Device: item.device})
			if callErr != nil {
				errCh <- callErr
				return
			}
			if acc.Items[0].Device != item.device || acc.Items[0].Status != resource.AttachmentDetaching {
				errCh <- fmt.Errorf("detach %s %+v", item.device, acc.Items[0])
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for callErr := range errCh {
		t.Errorf("concurrent detach: %v", callErr)
	}
	vols := world.volumeNames(instanceName(projectID, instID))
	if len(vols) != 1 || vols[0] != volumeName(projectID, rootID) {
		t.Fatalf("volumes after concurrent detach %v", vols)
	}
}

func TestAttachAndDetachDoNotRestoreAVolume(t *testing.T) {
	account := mustAccount(t)
	projectID := project(account)
	const (
		instID  = "i-0123456789abcdef0"
		rootID  = "vol-0123456789abcdef0"
		leftID  = "vol-0fedcba9876543210"
		rightID = "vol-0abcdef0123456789"
	)
	holder := observedInstance(projectID, instID,
		commonv1.ReconciliationState_RECONCILIATION_STATE_READY,
		computev1.InstancePower_INSTANCE_POWER_RUNNING)
	holder.Spec.Volumes = []*computev1.VolumeAttachment{
		{Volume: volumeName(projectID, rootID), DeviceName: "boot", Boot: true},
		{Volume: volumeName(projectID, leftID), DeviceName: "/dev/sdf"},
	}
	world := &detachWorld{
		inst: []*computev1.Instance{holder},
		vol:  observedVolume(projectID, leftID, commonv1.ReconciliationState_RECONCILIATION_STATE_READY, instID),
		more: []*storagev1.Volume{
			observedVolume(projectID, rightID, commonv1.ReconciliationState_RECONCILIATION_STATE_READY, ""),
		},
		byRequest: map[string]*detachRecord{},
		gate: &detachGate{
			release: make(chan struct{}),
			writes:  make(chan struct{}),
		},
	}
	client := dialDetachWorld(t, world)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	scope := backend.Scope{Account: account}
	left, err := resource.Parse[resource.VolumeID](leftID)
	if err != nil {
		t.Fatal(err)
	}
	right, err := resource.Parse[resource.VolumeID](rightID)
	if err != nil {
		t.Fatal(err)
	}
	holderID, err := resource.Parse[resource.InstanceID](instID)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errCh := make(chan error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, callErr := client.DetachVolume(ctx, backend.Mutation{
			Scope: scope, Key: "k-left", Fingerprint: "fp-left",
		}, resource.DetachVolumeRequest{VolumeID: left, InstanceID: holderID, Device: "/dev/sdf"})
		if callErr != nil {
			errCh <- callErr
		}
	}()
	go func() {
		defer wg.Done()
		acc, callErr := client.AttachVolume(ctx, backend.Mutation{
			Scope: scope, Key: "k-right", Fingerprint: "fp-right",
		}, resource.AttachVolumeRequest{VolumeID: right, InstanceID: holderID, Device: "/dev/sdg"})
		if callErr != nil {
			errCh <- callErr
			return
		}
		if acc.Items[0].Device != "/dev/sdg" || acc.Items[0].State != resource.VolumeInUse {
			errCh <- fmt.Errorf("attach %+v", acc.Items[0])
		}
	}()
	wg.Wait()
	close(errCh)
	for callErr := range errCh {
		t.Errorf("race: %v", callErr)
	}
	vols := world.volumeNames(instanceName(projectID, instID))
	want := []string{volumeName(projectID, rootID), volumeName(projectID, rightID)}
	if len(vols) != len(want) || vols[0] != want[0] || vols[1] != want[1] {
		t.Fatalf("volumes after attach and detach %v", vols)
	}
}

func TestDetachFindsABindPastPageFifty(t *testing.T) {
	account := mustAccount(t)
	projectID := project(account)
	const pages = 51
	dataID := "vol-00000051"
	instID := fmt.Sprintf("i-%08x", pages)
	pagesOf := make([]*computev1.Instance, pages)
	for i := 1; i <= pages; i++ {
		id := fmt.Sprintf("i-%08x", i)
		inst := observedInstance(projectID, id,
			commonv1.ReconciliationState_RECONCILIATION_STATE_READY,
			computev1.InstancePower_INSTANCE_POWER_RUNNING)
		inst.Spec.Volumes = []*computev1.VolumeAttachment{
			{Volume: volumeName(projectID, fmt.Sprintf("vol-%08x", i)), DeviceName: "boot", Boot: true},
		}
		pagesOf[i-1] = inst
	}
	holder := pagesOf[pages-1]
	holder.Spec.Volumes = append(holder.Spec.Volumes, &computev1.VolumeAttachment{
		Volume: volumeName(projectID, dataID), DeviceName: "/dev/sdf",
	})
	world := &detachWorld{
		inst:      []*computev1.Instance{holder},
		pages:     pagesOf,
		vol:       observedVolume(projectID, dataID, commonv1.ReconciliationState_RECONCILIATION_STATE_READY, ""),
		byRequest: map[string]*detachRecord{},
	}
	client := dialDetachWorld(t, world)
	data, err := resource.Parse[resource.VolumeID](dataID)
	if err != nil {
		t.Fatal(err)
	}
	want, err := resource.Parse[resource.InstanceID](instID)
	if err != nil {
		t.Fatal(err)
	}
	acc, err := client.DetachVolume(context.Background(), backend.Mutation{
		Scope: backend.Scope{Account: account}, Key: "k-page", Fingerprint: "fp-page",
	}, resource.DetachVolumeRequest{VolumeID: data})
	if err != nil {
		t.Fatal(err)
	}
	if acc.Items[0].InstanceID != want || acc.Items[0].Device != "/dev/sdf" ||
		acc.Items[0].Status != resource.AttachmentDetaching {
		t.Fatalf("page 51 %+v", acc.Items[0])
	}
}

func TestDetachPageTokenRepeatIsAnError(t *testing.T) {
	account := mustAccount(t)
	projectID := project(account)
	filler := observedInstance(projectID, "i-0123456789abcdef0",
		commonv1.ReconciliationState_RECONCILIATION_STATE_READY,
		computev1.InstancePower_INSTANCE_POWER_RUNNING)
	filler.Spec.Volumes = []*computev1.VolumeAttachment{
		{Volume: volumeName(projectID, "vol-0123456789abcdef0"), DeviceName: "boot", Boot: true},
	}
	world := &detachWorld{
		inst:        []*computev1.Instance{filler},
		repeatToken: true,
		vol: observedVolume(
			projectID, "vol-0fedcba9876543210",
			commonv1.ReconciliationState_RECONCILIATION_STATE_READY, "",
		),
		byRequest: map[string]*detachRecord{},
	}
	client := dialDetachWorld(t, world)
	data, err := resource.Parse[resource.VolumeID]("vol-0fedcba9876543210")
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.DetachVolume(context.Background(), backend.Mutation{
		Scope: backend.Scope{Account: account}, Key: "k-loop", Fingerprint: "fp-loop",
	}, resource.DetachVolumeRequest{VolumeID: data})
	if resource.CodeOf(err) != resource.CodeInternal {
		t.Fatalf("repeated page token: %v", err)
	}
}

func TestDetachReplayAfterStatusCleared(t *testing.T) {
	account := mustAccount(t)
	projectID := project(account)
	const (
		instID = "i-0123456789abcdef0"
		rootID = "vol-0123456789abcdef0"
		dataID = "vol-0fedcba9876543210"
	)
	holder := observedInstance(projectID, instID,
		commonv1.ReconciliationState_RECONCILIATION_STATE_READY,
		computev1.InstancePower_INSTANCE_POWER_RUNNING)
	holder.CreateTime = timestamppb.New(time.Unix(1_700_000_100, 0).UTC())
	holder.Spec.Volumes = []*computev1.VolumeAttachment{
		{Volume: volumeName(projectID, rootID), DeviceName: "boot", Boot: true},
		{Volume: volumeName(projectID, dataID), DeviceName: "/dev/sdf"},
	}
	dataVol := observedVolume(projectID, dataID, commonv1.ReconciliationState_RECONCILIATION_STATE_READY, instID)
	dataVol.Status.DeviceName = "/dev/sdf"
	world := &detachWorld{
		inst:      []*computev1.Instance{holder},
		vol:       dataVol,
		byRequest: map[string]*detachRecord{},
	}
	client := dialDetachWorld(t, world)
	ctx := context.Background()
	data, err := resource.Parse[resource.VolumeID](dataID)
	if err != nil {
		t.Fatal(err)
	}
	holderID, err := resource.Parse[resource.InstanceID](instID)
	if err != nil {
		t.Fatal(err)
	}
	mut := backend.Mutation{Scope: backend.Scope{Account: account}, Key: "k-cleared", Fingerprint: "fp-cleared"}
	first, err := client.DetachVolume(ctx, mut, resource.DetachVolumeRequest{
		VolumeID: data, InstanceID: holderID,
	})
	if err != nil {
		t.Fatal(err)
	}
	world.finishAll()
	dataVol.Status.Instance = ""
	dataVol.Status.DeviceName = ""
	again, err := client.DetachVolume(ctx, mut, resource.DetachVolumeRequest{VolumeID: data})
	if err != nil {
		t.Fatalf("volume-only replay after status cleared: %v", err)
	}
	if again.Operation.ID != first.Operation.ID || again.Items[0].Device != "/dev/sdf" ||
		again.Items[0].InstanceID != holderID || again.Items[0].Status != resource.AttachmentDetaching {
		t.Fatalf("replay %+v op %s, first %s", again.Items[0], again.Operation.ID, first.Operation.ID)
	}
}

func TestRejectedDetachDoesNotReplay(t *testing.T) {
	account := mustAccount(t)
	projectID := project(account)
	const (
		instID = "i-0123456789abcdef0"
		rootID = "vol-0123456789abcdef0"
		dataID = "vol-0fedcba9876543210"
	)
	holder := observedInstance(projectID, instID,
		commonv1.ReconciliationState_RECONCILIATION_STATE_READY,
		computev1.InstancePower_INSTANCE_POWER_RUNNING)
	holder.Spec.Volumes = []*computev1.VolumeAttachment{
		{Volume: volumeName(projectID, rootID), DeviceName: "boot", Boot: true},
	}
	world := &detachWorld{
		inst:      []*computev1.Instance{holder},
		vol:       observedVolume(projectID, dataID, commonv1.ReconciliationState_RECONCILIATION_STATE_READY, ""),
		byRequest: map[string]*detachRecord{},
	}
	client := dialDetachWorld(t, world)
	data, err := resource.Parse[resource.VolumeID](dataID)
	if err != nil {
		t.Fatal(err)
	}
	holderID, err := resource.Parse[resource.InstanceID](instID)
	if err != nil {
		t.Fatal(err)
	}
	mut := backend.Mutation{Scope: backend.Scope{Account: account}, Key: "k-reject", Fingerprint: "fp-reject"}
	req := resource.DetachVolumeRequest{VolumeID: data, InstanceID: holderID, Device: "/dev/sdf"}
	_, err = client.DetachVolume(context.Background(), mut, req)
	if resource.CodeOf(err) != resource.CodeConflict || world.updateCount() != 0 {
		t.Fatalf("rejected detach: %v updates %d", err, world.updateCount())
	}
	_, err = client.DetachVolume(context.Background(), mut, req)
	if resource.CodeOf(err) != resource.CodeConflict || world.updateCount() != 0 {
		t.Fatalf("repeated rejected token: %v updates %d", err, world.updateCount())
	}
}

func TestDetachReplaySurvivesAnotherVolume(t *testing.T) {
	account := mustAccount(t)
	projectID := project(account)
	const (
		instID  = "i-0123456789abcdef0"
		rootID  = "vol-0123456789abcdef0"
		leftID  = "vol-0fedcba9876543210"
		rightID = "vol-0abcdef0123456789"
	)
	holder := observedInstance(projectID, instID,
		commonv1.ReconciliationState_RECONCILIATION_STATE_READY,
		computev1.InstancePower_INSTANCE_POWER_RUNNING)
	holder.Spec.Volumes = []*computev1.VolumeAttachment{
		{Volume: volumeName(projectID, rootID), DeviceName: "boot", Boot: true},
		{Volume: volumeName(projectID, leftID), DeviceName: "/dev/sdf"},
		{Volume: volumeName(projectID, rightID), DeviceName: "/dev/sdg"},
	}
	world := &detachWorld{
		inst: []*computev1.Instance{holder},
		vol:  observedVolume(projectID, leftID, commonv1.ReconciliationState_RECONCILIATION_STATE_READY, instID),
		more: []*storagev1.Volume{
			observedVolume(projectID, rightID, commonv1.ReconciliationState_RECONCILIATION_STATE_READY, instID),
		},
		byRequest: map[string]*detachRecord{},
	}
	client := dialDetachWorld(t, world)
	ctx := context.Background()
	scope := backend.Scope{Account: account}
	left, err := resource.Parse[resource.VolumeID](leftID)
	if err != nil {
		t.Fatal(err)
	}
	right, err := resource.Parse[resource.VolumeID](rightID)
	if err != nil {
		t.Fatal(err)
	}
	holderID, err := resource.Parse[resource.InstanceID](instID)
	if err != nil {
		t.Fatal(err)
	}
	mutA := backend.Mutation{Scope: scope, Key: "k-a", Fingerprint: "fp-a"}
	first, err := client.DetachVolume(ctx, mutA, resource.DetachVolumeRequest{
		VolumeID: left, InstanceID: holderID,
	})
	if err != nil {
		t.Fatal(err)
	}
	mutB := backend.Mutation{Scope: scope, Key: "k-b", Fingerprint: "fp-b"}
	_, err = client.DetachVolume(ctx, mutB, resource.DetachVolumeRequest{
		VolumeID: right, InstanceID: holderID,
	})
	if err != nil {
		t.Fatal(err)
	}
	again, err := client.DetachVolume(ctx, mutA, resource.DetachVolumeRequest{VolumeID: left})
	if err != nil {
		t.Fatalf("retry A after B: %v", err)
	}
	if again.Operation.ID != first.Operation.ID || again.Items[0].Device != "/dev/sdf" ||
		again.Items[0].Status != resource.AttachmentDetaching {
		t.Fatalf("retry A %+v op %s, first %s", again.Items[0], again.Operation.ID, first.Operation.ID)
	}
	vols := world.volumeNames(instanceName(projectID, instID))
	if len(vols) != 1 || vols[0] != volumeName(projectID, rootID) {
		t.Fatalf("volumes after retry A %v", vols)
	}
}

func assertDetachLabels(t *testing.T, labels map[string]string) {
	t.Helper()
	if labels[labelImage] != "ami-0123456789abcdef0" || labels[labelReservation] != "r-01234567" ||
		labels[labelLaunch] != "launch-1" || labels["env"] != "dev" {
		t.Fatalf("labels %+v", labels)
	}
}
