package grpcclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"slices"
	"strconv"
	"time"

	longrunningpb "cloud.google.com/go/longrunning/autogen/longrunningpb"
	computev1 "github.com/popododo0720/vws-proto/gen/go/vws/compute/v1"
	networkv1 "github.com/popododo0720/vws-proto/gen/go/vws/network/v1"
	storagev1 "github.com/popododo0720/vws-proto/gen/go/vws/storage/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// api is one process's view of the resource API. RunInstances talks to
// volumes and subnets as well as instances, so the three backend views share it.
type api struct {
	instances  computev1.InstanceServiceClient
	volumes    storagev1.VolumeServiceClient
	buckets    storagev1.BucketServiceClient
	objects    storagev1.ObjectServiceClient
	subnets    networkv1.SubnetServiceClient
	vpcs       networkv1.VpcServiceClient
	groups     networkv1.SecurityGroupServiceClient
	keys       computev1.KeyPairServiceClient
	addresses  networkv1.AddressServiceClient
	snapshots  storagev1.SnapshotServiceClient
	computeOps longrunningpb.OperationsClient
	storageOps longrunningpb.OperationsClient
	networkOps longrunningpb.OperationsClient
	log        *slog.Logger
}

type computeClient struct{ *api }

func (c computeClient) RunInstances(ctx context.Context, m backend.Mutation, req resource.RunInstancesRequest) (resource.Accepted[resource.Instance], error) {
	if req.Count < 1 {
		return resource.Accepted[resource.Instance]{}, resource.Invalid("count", "must be from 1 to 10")
	}
	projectID := project(m.Account)
	subnet, err := c.findSubnet(ctx, projectID, req.SubnetID.String())
	if err != nil {
		return resource.Accepted[resource.Instance]{}, err
	}
	keyPair := ""
	if req.KeyName != "" {
		key, err := c.findKey(ctx, projectID, resource.DeleteKeyPairRequest{Name: req.KeyName})
		if err != nil {
			return resource.Accepted[resource.Instance]{}, err
		}
		keyPair = keyPairName(projectID, key.ID.String())
	}
	if !resource.CanLaunchImage(m.Account, req.ImageID) {
		return resource.Accepted[resource.Instance]{}, resource.ImageNotFound(req.ImageID)
	}
	items := make([]resource.Instance, 0, req.Count)
	var op resource.Operation
	// One launch is one reservation. A retry with the same key derives the same id.
	reservation := derivedID("r-", m.Key, "reservation")
	labels, err := withInternalLabels(req.Tags, map[string]string{
		labelFingerprint: clip(m.Fingerprint, 63),
		labelImage:       req.ImageID.String(),
		labelLaunch:      clip(m.Key, 32),
		labelReservation: reservation,
	})
	if err != nil {
		return resource.Accepted[resource.Instance]{}, err
	}
	for i := 0; i < req.Count; i++ {
		volID := derivedID("vol-", m.Key, "vol", strconv.Itoa(i))
		instID := derivedID("i-", m.Key, "inst", strconv.Itoa(i))
		volOp, err := c.volumes.CreateVolume(ctx, &storagev1.CreateVolumeRequest{
			Parent:    volumeParent(projectID),
			VolumeId:  volID,
			RequestId: requestUUID(m.Key, "vol", strconv.Itoa(i)),
			Volume:    bootVolume(projectID, m.Fingerprint, req.ImageID, instID),
		})
		if err := rpcErr(volOp, err); err != nil {
			return resource.Accepted[resource.Instance]{}, err
		}
		created, err := c.instances.CreateInstance(ctx, &computev1.CreateInstanceRequest{
			Parent:     instanceParent(projectID),
			InstanceId: instID,
			RequestId:  requestUUID(m.Key, "inst", strconv.Itoa(i)),
			Instance: &computev1.Instance{
				Labels: labels,
				Spec: &computev1.InstanceSpec{
					MachineType: req.InstanceType,
					Power:       computev1.InstancePower_INSTANCE_POWER_RUNNING,
					KeyPair:     keyPair,
					UserData:    req.UserData,
					NetworkInterfaces: []*computev1.NetworkInterface{{
						DeviceName: "nic0",
						Subnet:     subnet,
					}},
					Volumes: []*computev1.VolumeAttachment{{
						Volume:     volumeName(projectID, volID),
						DeviceName: "boot",
						Boot:       true,
					}},
				},
			},
		})
		if err := rpcErr(created, err); err != nil {
			return resource.Accepted[resource.Instance]{}, err
		}
		metaName, err := metadataResource(created)
		if err != nil {
			return resource.Accepted[resource.Instance]{}, err
		}
		got, err := c.instances.GetInstance(ctx, &computev1.GetInstanceRequest{Name: metaName})
		if err != nil {
			return resource.Accepted[resource.Instance]{}, fromRPC(err)
		}
		inst, err := instanceModel(got)
		if err != nil {
			return resource.Accepted[resource.Instance]{}, err
		}
		inst.KeyName = req.KeyName
		items = append(items, inst)
		if i == 0 {
			op, err = operationFrom(created, resource.ServiceCompute)
			if err != nil {
				return resource.Accepted[resource.Instance]{}, err
			}
		}
	}
	op.Action = resource.ActionRunInstances
	op.Targets = instanceRefs(items)
	return resource.Accepted[resource.Instance]{Operation: op, Items: items}, nil
}

// bootVolume is the disk RunInstances creates from the machine image.
// volume.proto sources a volume from a compute image. InstanceSpec has no
// image field; the instance attaches this volume and marks it boot.
func bootVolume(projectID, fingerprint string, image resource.ImageID, instance string) *storagev1.Volume {
	return &storagev1.Volume{
		Labels: map[string]string{labelFingerprint: clip(fingerprint, 63), labelInstance: instance},
		Spec: &storagev1.VolumeSpec{
			SizeGib: 8,
			Type:    storagev1.VolumeType_VOLUME_TYPE_SSD,
			Source:  &storagev1.VolumeSpec_Image{Image: imageName(projectID, image.String())},
		},
	}
}

func (c computeClient) StopInstances(ctx context.Context, m backend.Mutation, req resource.StopInstancesRequest) (resource.Accepted[resource.InstanceStateChange], error) {
	projectID := project(m.Account)
	prev := make([]resource.Instance, 0, len(req.IDs))
	for _, id := range req.IDs {
		inst, err := c.getInstance(ctx, projectID, id.String())
		if err != nil {
			return resource.Accepted[resource.InstanceStateChange]{}, err
		}
		if _, _, err := resource.NextInstanceState(resource.ActionStopInstances, inst.State); err != nil {
			return resource.Accepted[resource.InstanceStateChange]{}, err
		}
		prev = append(prev, inst)
	}
	var op resource.Operation
	items := make([]resource.InstanceStateChange, 0, len(prev))
	for i, inst := range prev {
		var mid resource.InstanceState
		// writeInstanceLabels keeps the detach records compute would drop
		// with a whole-map label replace (#213).
		updated, cur, err := c.writeInstanceLabels(ctx, projectID, inst.ID, func(
			got *computev1.Instance, model resource.Instance,
		) (*computev1.UpdateInstanceRequest, error) {
			next, _, err := resource.NextInstanceState(resource.ActionStopInstances, model.State)
			if err != nil {
				return nil, err
			}
			mid = next
			labels, err := instanceUpdateLabels(model, got.GetLabels(), resource.ActionStopInstances, m.Fingerprint, nil)
			if err != nil {
				return nil, err
			}
			return &computev1.UpdateInstanceRequest{
				RequestId:  requestUUID(m.Key, "stop", strconv.Itoa(i)),
				UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"spec.power", "labels"}},
				Instance: &computev1.Instance{
					Name:   got.GetName(),
					Labels: labels,
					Spec: &computev1.InstanceSpec{
						MachineType: model.InstanceType,
						Power:       computev1.InstancePower_INSTANCE_POWER_STOPPED,
						NetworkInterfaces: []*computev1.NetworkInterface{{
							DeviceName: "nic0",
							Subnet:     subnetName(projectID, "", model.SubnetID.String()),
						}},
					},
				},
			}, nil
		})
		if err != nil {
			return resource.Accepted[resource.InstanceStateChange]{}, err
		}
		inst = cur
		if i == 0 {
			op, err = operationFrom(updated, resource.ServiceCompute)
			if err != nil {
				return resource.Accepted[resource.InstanceStateChange]{}, err
			}
		}
		items = append(items, resource.InstanceStateChange{
			ID: inst.ID, OwnerID: inst.OwnerID, Previous: inst.State, Current: mid,
		})
	}
	op.Action = resource.ActionStopInstances
	op.Targets = make([]resource.Ref, 0, len(items))
	for _, item := range items {
		op.Targets = append(op.Targets, item.ID.Ref())
	}
	return resource.Accepted[resource.InstanceStateChange]{Operation: op, Items: items}, nil
}

func (c computeClient) DescribeInstances(ctx context.Context, s backend.Scope, q resource.InstanceQuery) (resource.Page[resource.Instance], error) {
	projectID := project(s.Account)
	if len(q.IDs) == 1 {
		inst, err := c.getInstance(ctx, projectID, q.IDs[0].String())
		if err != nil {
			return resource.Page[resource.Instance]{}, err
		}
		if !stateWanted(inst.State, q.States) {
			return resource.Page[resource.Instance]{}, nil
		}
		items := []resource.Instance{inst}
		if err := c.nameKeys(ctx, projectID, items); err != nil {
			return resource.Page[resource.Instance]{}, err
		}
		return pageInstances(items, q.Page)
	}
	if len(q.IDs) > 1 {
		items := make([]resource.Instance, 0, len(q.IDs))
		for _, id := range q.IDs {
			inst, err := c.getInstance(ctx, projectID, id.String())
			if resource.CodeOf(err) == resource.CodeNotFound {
				continue
			}
			if err != nil {
				return resource.Page[resource.Instance]{}, err
			}
			if stateWanted(inst.State, q.States) {
				items = append(items, inst)
			}
		}
		if err := c.nameKeys(ctx, projectID, items); err != nil {
			return resource.Page[resource.Instance]{}, err
		}
		return pageInstances(items, q.Page)
	}
	out, err := c.instances.ListInstances(ctx, &computev1.ListInstancesRequest{
		Parent:    instanceParent(projectID),
		PageSize:  pageSize(q.Page.Size),
		PageToken: q.Page.Token,
	})
	if err != nil {
		return resource.Page[resource.Instance]{}, fromRPC(err)
	}
	items := make([]resource.Instance, 0, len(out.GetInstances()))
	for _, item := range out.GetInstances() {
		inst, err := instanceModel(item)
		if err != nil {
			if c.skipBadRecord(ctx, item.GetName(), err) {
				continue
			}
			return resource.Page[resource.Instance]{}, err
		}
		if stateWanted(inst.State, q.States) {
			items = append(items, inst)
		}
	}
	if err := c.nameKeys(ctx, projectID, items); err != nil {
		return resource.Page[resource.Instance]{}, err
	}
	return resource.Page[resource.Instance]{Items: items, NextToken: out.GetNextPageToken()}, nil
}

// nameKeys fills KeyName from the key pair each instance spec names. Compute
// refuses to delete a key pair an instance names, so the key is there to read.
// It lists key pairs only when some instance has one.
func (c computeClient) nameKeys(ctx context.Context, projectID string, items []resource.Instance) error {
	if !slices.ContainsFunc(items, func(i resource.Instance) bool { return !i.KeyPairID.IsZero() }) {
		return nil
	}
	keys, err := c.listKeys(ctx, projectID)
	if err != nil {
		return err
	}
	names := make(map[resource.KeyPairID]string, len(keys))
	for _, key := range keys {
		names[key.ID] = key.Name
	}
	for i := range items {
		if !items[i].KeyPairID.IsZero() {
			items[i].KeyName = names[items[i].KeyPairID]
		}
	}
	return nil
}

func (c computeClient) GetOperation(ctx context.Context, s backend.Scope, id resource.OperationID) (resource.Operation, error) {
	name := operationName(project(s.Account), id.Local())
	out, err := c.computeOps.GetOperation(ctx, &longrunningpb.GetOperationRequest{Name: name})
	if status.Code(err) == codes.NotFound {
		out, err = c.storageOps.GetOperation(ctx, &longrunningpb.GetOperationRequest{Name: name})
	}
	if err != nil {
		return resource.Operation{}, fromRPC(err)
	}
	op, err := operationFrom(out, resource.ServiceCompute)
	if err != nil {
		return resource.Operation{}, err
	}
	if op.ID != id {
		return resource.Operation{}, resource.Internal(errors.New("backend returned a different operation"))
	}
	return c.actionFromInstance(ctx, s, op)
}

// actionFromInstance reads the vws-action label. Verb plus resource cannot
// tell a start from a stop, and a real request id is a UUID.
func (c computeClient) actionFromInstance(ctx context.Context, s backend.Scope, op resource.Operation) (resource.Operation, error) {
	if op.Action != resource.ActionStopInstances || len(op.Targets) != 1 || op.Targets[0].Kind() != resource.KindInstance {
		return op, nil
	}
	got, err := c.instances.GetInstance(ctx, &computev1.GetInstanceRequest{
		Name: instanceName(project(s.Account), op.Targets[0].ID()),
	})
	if status.Code(err) == codes.NotFound {
		return op, nil
	}
	if err != nil {
		return resource.Operation{}, fromRPC(err)
	}
	if parsed, ok := resource.ParseAction(got.GetLabels()[labelAction]); ok {
		op.Action = parsed
	}
	return op, nil
}

func (c computeClient) getInstance(ctx context.Context, projectID, id string) (resource.Instance, error) {
	name := instanceName(projectID, id)
	out, err := c.instances.GetInstance(ctx, &computev1.GetInstanceRequest{Name: name})
	if err != nil {
		return resource.Instance{}, fromNamedRPC(name, err)
	}
	return instanceModel(out)
}

func (c computeClient) findSubnet(ctx context.Context, projectID, id string) (string, error) {
	token := ""
	for page := 0; page < 20; page++ {
		out, err := c.vpcs.ListVpcs(ctx, &networkv1.ListVpcsRequest{
			Parent: regionParent(projectID), PageSize: 100, PageToken: token,
		})
		if err != nil {
			return "", fromRPC(err)
		}
		for _, vpc := range out.GetVpcs() {
			found, err := c.findSubnetIn(ctx, vpc.GetName(), id)
			if err != nil {
				return "", err
			}
			if found != "" {
				return found, nil
			}
		}
		token = out.GetNextPageToken()
		if token == "" {
			break
		}
	}
	return "", resource.NotFound(resource.KindSubnet, id)
}

func (c computeClient) findSubnetIn(ctx context.Context, parent, id string) (string, error) {
	token := ""
	for page := 0; page < 20; page++ {
		out, err := c.subnets.ListSubnets(ctx, &networkv1.ListSubnetsRequest{
			Parent: parent, PageSize: 100, PageToken: token,
		})
		if err != nil {
			return "", fromRPC(err)
		}
		for _, sub := range out.GetSubnets() {
			if lastSegment(sub.GetName()) == id {
				return sub.GetName(), nil
			}
		}
		token = out.GetNextPageToken()
		if token == "" {
			break
		}
	}
	return "", nil
}

type storageClient struct{ *api }

// CreateBucket creates a bucket the caller does not hold yet (#315). A bucket
// the caller already owns is BucketAlreadyOwned. vws-storage answers a
// create for a bucket the project holds with a succeeded operation
// (operation.proto, Create), so the client asks first.
//
// Each call sends a request id of its own. vws-storage returns the stored
// operation for any request id it has seen, so a fixed id per name would
// answer a create after DeleteBucket with the first create's operation, and
// no bucket. An operation that names another request id is a create
// already in flight for this project, so the caller owns the name.
func (c storageClient) CreateBucket(ctx context.Context, s backend.Scope, name resource.BucketName) (resource.Bucket, error) {
	switch _, err := c.GetBucket(ctx, s, name); {
	case err == nil:
		return resource.Bucket{}, resource.BucketAlreadyOwned(name.String())
	case resource.CodeOf(err) != resource.CodeNotFound:
		return resource.Bucket{}, err
	}
	projectID := project(s.Account)
	nonce, err := newNonce()
	if err != nil {
		return resource.Bucket{}, err
	}
	requestID := requestUUID(projectID, name.String(), "bucket", nonce)
	op, err := c.buckets.CreateBucket(ctx, &storagev1.CreateBucketRequest{
		Parent:    bucketParent(projectID),
		BucketId:  name.String(),
		RequestId: requestID,
		Bucket: &storagev1.Bucket{
			Spec: &storagev1.BucketSpec{Region: resource.RegionName},
		},
	})
	if err := rpcErr(op, err); err != nil {
		return resource.Bucket{}, err
	}
	other, err := operationRequestID(op)
	if err != nil {
		return resource.Bucket{}, err
	}
	if other != "" && other != requestID {
		return resource.Bucket{}, resource.BucketAlreadyOwned(name.String())
	}
	if bucket, ok, err := unpackBucket(op); err != nil || ok {
		if err != nil {
			return resource.Bucket{}, err
		}
		return bucket, nil
	}
	return c.GetBucket(ctx, s, name)
}

func (c storageClient) GetBucket(ctx context.Context, s backend.Scope, name resource.BucketName) (resource.Bucket, error) {
	out, err := c.buckets.GetBucket(ctx, &storagev1.GetBucketRequest{Name: bucketName(project(s.Account), name.String())})
	if err != nil {
		return resource.Bucket{}, fromRPC(err)
	}
	return bucketModel(out)
}

func (c storageClient) ListBuckets(ctx context.Context, s backend.Scope, q resource.BucketQuery) (resource.Page[resource.Bucket], error) {
	out, err := c.buckets.ListBuckets(ctx, &storagev1.ListBucketsRequest{
		Parent:    bucketParent(project(s.Account)),
		PageSize:  pageSize(q.Page.Size),
		PageToken: q.Page.Token,
	})
	if err != nil {
		return resource.Page[resource.Bucket]{}, fromRPC(err)
	}
	items := make([]resource.Bucket, 0, len(out.GetBuckets()))
	for _, item := range out.GetBuckets() {
		b, err := bucketModel(item)
		if err != nil {
			return resource.Page[resource.Bucket]{}, err
		}
		items = append(items, b)
	}
	return resource.Page[resource.Bucket]{Items: items, NextToken: out.GetNextPageToken()}, nil
}

// DeleteBucket sends a request id of its own on each call, for the reason
// CreateBucket does: a fixed id per name would answer a delete of a bucket
// created again with the earlier delete's operation and leave it (#315).
func (c storageClient) DeleteBucket(ctx context.Context, s backend.Scope, name resource.BucketName) error {
	nonce, err := newNonce()
	if err != nil {
		return err
	}
	op, err := c.buckets.DeleteBucket(ctx, &storagev1.DeleteBucketRequest{
		Name:      bucketName(project(s.Account), name.String()),
		RequestId: requestUUID(project(s.Account), name.String(), "delete-bucket", nonce),
	})
	return rpcErr(op, err)
}

func (c storageClient) PutObject(ctx context.Context, s backend.Scope, req resource.PutObjectRequest, body io.Reader) (resource.Object, error) {
	if req.Size > resource.MaxObjectBytes {
		return resource.Object{}, resource.TooLarge("object exceeds 4 MiB")
	}
	buf, err := io.ReadAll(io.LimitReader(body, resource.MaxObjectBytes+1))
	if err != nil {
		return resource.Object{}, resource.Internal(err)
	}
	if len(buf) > resource.MaxObjectBytes {
		return resource.Object{}, resource.TooLarge("object exceeds 4 MiB")
	}
	if req.Size >= 0 && int64(len(buf)) != req.Size {
		return resource.Object{}, resource.Invalid("size", "body length does not match")
	}
	projectID := project(s.Account)
	name := objectName(projectID, req.Bucket.String(), req.Key.String())
	if req.IfNoneMatch {
		return c.createObject(ctx, projectID, name, req, buf)
	}
	op, err := c.objects.UpdateObject(ctx, &storagev1.UpdateObjectRequest{
		AllowMissing: true,
		Contents:     buf,
		RequestId:    putRequestID(projectID, req.Bucket.String(), req.Key.String(), buf),
		UpdateMask:   objectUpdateMask(),
		Object: &storagev1.Object{
			Name:   name,
			Labels: map[string]string{},
			Spec:   &storagev1.ObjectSpec{ContentType: req.ContentType, Sha256: hex.EncodeToString(sha256Of(buf))},
		},
	})
	if err := rpcErr(op, err); err != nil {
		return resource.Object{}, err
	}
	return c.finishPut(ctx, name, op)
}

// createObject is PutObject with If-None-Match: *. CreateObject refuses an
// existing key atomically when the bytes differ. vws-storage accepts a create
// whose bytes match the stored object, so an existing key is checked first.
// Two creates racing with identical bytes can both succeed until storage has
// a strict create (see the PR).
func (c storageClient) createObject(ctx context.Context, projectID, name string, req resource.PutObjectRequest, buf []byte) (resource.Object, error) {
	exists := resource.AlreadyExists(resource.KindObject, req.Key.String())
	_, err := c.objects.GetObject(ctx, &storagev1.GetObjectRequest{Name: name})
	if err == nil {
		return resource.Object{}, exists
	}
	if mapped := fromRPC(err); resource.CodeOf(mapped) != resource.CodeNotFound {
		return resource.Object{}, mapped
	}
	op, err := c.objects.CreateObject(ctx, &storagev1.CreateObjectRequest{
		Parent:    bucketName(projectID, req.Bucket.String()),
		ObjectId:  encodeObjectKey(req.Key.String()),
		Contents:  buf,
		RequestId: requestUUID(projectID, req.Bucket.String(), req.Key.String(), "create", hex.EncodeToString(sha256Of(buf))),
		Object: &storagev1.Object{
			Labels: map[string]string{},
			Spec:   &storagev1.ObjectSpec{ContentType: req.ContentType, Sha256: hex.EncodeToString(sha256Of(buf))},
		},
	})
	if err := rpcErr(op, err); err != nil {
		if resource.CodeOf(err) == resource.CodeAlreadyExists {
			return resource.Object{}, exists
		}
		return resource.Object{}, err
	}
	return c.finishPut(ctx, name, op)
}

func sha256Of(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

// finishPut waits for a put and returns the stored object.
func (c storageClient) finishPut(ctx context.Context, name string, op *longrunningpb.Operation) (resource.Object, error) {
	op, err := c.awaitStorage(ctx, op)
	if err != nil {
		return resource.Object{}, err
	}
	obj, ok, err := unpackObject(op)
	if err != nil {
		return resource.Object{}, err
	}
	if ok && obj.ETag != "" {
		return obj, nil
	}
	out, err := c.objects.GetObject(ctx, &storagev1.GetObjectRequest{Name: name})
	if err != nil {
		return resource.Object{}, fromRPC(err)
	}
	return objectModel(out)
}

// awaitStorage polls a put until the storage service marks it done. The
// object is not readable until then, so GetObject before that is NotFound.
func (c storageClient) awaitStorage(ctx context.Context, op *longrunningpb.Operation) (*longrunningpb.Operation, error) {
	if op.GetDone() {
		return op, nil
	}
	name := op.GetName()
	if name == "" {
		return nil, resource.Internal(errors.New("missing operation"))
	}
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		got, err := c.storageOps.GetOperation(ctx, &longrunningpb.GetOperationRequest{Name: name})
		if err != nil {
			return nil, fromRPC(err)
		}
		if got.GetDone() {
			if got.GetError() != nil {
				return nil, fromRPC(status.ErrorProto(got.GetError()))
			}
			return got, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

// putRequestID includes the payload hash. The storage service treats request
// id as the idempotency key, so a key of only project, bucket, and object
// rejects an overwrite as a reused client token.
func putRequestID(projectID, bucket, key string, body []byte) string {
	sum := sha256.Sum256(body)
	return requestUUID(projectID, bucket, key, "put", hex.EncodeToString(sum[:]))
}

// objectUpdateMask is the mask vws-storage's objectMaskOK accepts for a write
// that replaces spec. An empty mask also passes; a spec-only mask does not.
// The same mask covers the first put and an overwrite.
func objectUpdateMask() *fieldmaskpb.FieldMask {
	return &fieldmaskpb.FieldMask{Paths: []string{"spec", "labels"}}
}

func objectMaskMatches(mask *fieldmaskpb.FieldMask) bool {
	paths := mask.GetPaths()
	if len(paths) == 0 {
		return true
	}
	if len(paths) != 2 {
		return false
	}
	spec, labels := false, false
	for _, path := range paths {
		switch path {
		case "spec":
			spec = true
		case "labels":
			labels = true
		default:
			return false
		}
	}
	return spec && labels
}

func (c storageClient) GetObject(ctx context.Context, s backend.Scope, req resource.GetObjectRequest) (resource.Object, io.ReadCloser, error) {
	out, err := c.objects.ReadObject(ctx, &storagev1.ReadObjectRequest{
		Name: objectName(project(s.Account), req.Bucket.String(), req.Key.String()),
	})
	if err != nil {
		return resource.Object{}, nil, c.objectErr(ctx, s, req.Bucket, req.Key, fromRPC(err))
	}
	if out.GetObject().GetDeleteTime() != nil {
		return resource.Object{}, nil, resource.NotFound(resource.KindObject, req.Key.String())
	}
	meta, err := objectModel(out.GetObject())
	if err != nil {
		return resource.Object{}, nil, err
	}
	return meta, io.NopCloser(bytes.NewReader(out.GetContents())), nil
}

func (c storageClient) ListObjects(ctx context.Context, s backend.Scope, q resource.ObjectQuery) (resource.ObjectListing, error) {
	q, err := q.Normalize()
	if err != nil {
		return resource.ObjectListing{}, err
	}
	// ListObjects has no prefix or delimiter. Read every page, then roll the
	// keys up once. The service token is not the caller's continuation token.
	// The project is "a" plus the account, the same as every other storage call.
	parent := bucketName(project(s.Account), q.Bucket.String())
	var keys []resource.Object
	serviceToken := ""
	for page := 0; page < 100; page++ {
		if err := ctx.Err(); err != nil {
			return resource.ObjectListing{}, err
		}
		out, err := c.objects.ListObjects(ctx, &storagev1.ListObjectsRequest{
			Parent: parent, PageSize: 1000, PageToken: serviceToken,
		})
		if err != nil {
			return resource.ObjectListing{}, fromRPC(err)
		}
		for _, item := range out.GetObjects() {
			if item.GetDeleteTime() != nil {
				continue
			}
			obj, err := objectModel(item)
			if err != nil {
				return resource.ObjectListing{}, err
			}
			if obj.Bucket != q.Bucket || obj.OwnerID != s.Account {
				return resource.ObjectListing{}, resource.Internal(errors.New("object from another account"))
			}
			keys = append(keys, obj)
		}
		next := out.GetNextPageToken()
		if next == "" {
			if len(keys) == 0 {
				if _, err := c.GetBucket(ctx, s, q.Bucket); err != nil {
					return resource.ObjectListing{}, err
				}
			}
			return resource.PageObjects(keys, q)
		}
		if next == serviceToken {
			return resource.ObjectListing{}, resource.Internal(errors.New("object listing is incomplete"))
		}
		serviceToken = next
	}
	return resource.ObjectListing{}, resource.Internal(errors.New("object listing is incomplete"))
}

func (c storageClient) DeleteObject(ctx context.Context, s backend.Scope, bucket resource.BucketName, key resource.ObjectKey) error {
	projectID := project(s.Account)
	op, err := c.objects.DeleteObject(ctx, &storagev1.DeleteObjectRequest{
		Name:         objectName(projectID, bucket.String(), key.String()),
		AllowMissing: true,
		RequestId:    requestUUID(projectID, bucket.String(), key.String(), "delete-object"),
	})
	return c.objectErr(ctx, s, bucket, key, rpcErr(op, err))
}

// objectErr names what is missing. vws-storage sends the same NotFound for a
// missing bucket and a missing object, so ask for the bucket to tell them apart.
func (c storageClient) objectErr(ctx context.Context, s backend.Scope, bucket resource.BucketName, key resource.ObjectKey, err error) error {
	if resource.CodeOf(err) != resource.CodeNotFound {
		return err
	}
	if _, bErr := c.GetBucket(ctx, s, bucket); bErr != nil {
		if resource.CodeOf(bErr) == resource.CodeNotFound {
			return resource.NotFound(resource.KindBucket, bucket.String())
		}
		return bErr
	}
	return resource.NotFound(resource.KindObject, key.String())
}

type networkClient struct{ *api }

func (c networkClient) CreateSubnet(ctx context.Context, m backend.Mutation, req resource.CreateSubnetRequest) (resource.Accepted[resource.Subnet], error) {
	projectID := project(m.Account)
	var vpcID, vpcCIDR string
	if req.VpcID.IsZero() {
		var err error
		vpcID, vpcCIDR, err = vpcForCIDR(req.Cidr)
		if err != nil {
			return resource.Accepted[resource.Subnet]{}, err
		}
	} else {
		vpcID = req.VpcID.String()
	}
	if req.VpcID.IsZero() {
		vpcOp, err := c.vpcs.CreateVpc(ctx, &networkv1.CreateVpcRequest{
			Parent:    regionParent(projectID),
			VpcId:     vpcID,
			RequestId: requestUUID(m.Key, "vpc"),
			Vpc: &networkv1.Vpc{
				Labels: map[string]string{labelFingerprint: clip(m.Fingerprint, 63)},
				Spec:   &networkv1.VpcSpec{Ipv4Cidr: vpcCIDR},
			},
		})
		if err := rpcErr(vpcOp, err); err != nil && resource.CodeOf(err) != resource.CodeAlreadyExists {
			return resource.Accepted[resource.Subnet]{}, err
		}
	}
	subnetID := derivedID("subnet-", m.Key, "subnet")
	labels, err := withInternalLabels(req.Tags, map[string]string{labelFingerprint: clip(m.Fingerprint, 63)})
	if err != nil {
		return resource.Accepted[resource.Subnet]{}, err
	}
	created, err := c.subnets.CreateSubnet(ctx, &networkv1.CreateSubnetRequest{
		Parent:    vpcName(projectID, vpcID),
		SubnetId:  subnetID,
		RequestId: requestUUID(m.Key, "subnet"),
		Subnet: &networkv1.Subnet{
			Labels: labels,
			Spec:   &networkv1.SubnetSpec{Zone: resource.ZoneName, Ipv4Cidr: req.Cidr},
		},
	})
	if err := rpcErr(created, err); err != nil {
		return resource.Accepted[resource.Subnet]{}, err
	}
	metaName, err := metadataResource(created)
	if err != nil {
		return resource.Accepted[resource.Subnet]{}, err
	}
	got, err := c.subnets.GetSubnet(ctx, &networkv1.GetSubnetRequest{Name: metaName})
	if err != nil {
		return resource.Accepted[resource.Subnet]{}, fromRPC(err)
	}
	sub, err := subnetModel(got)
	if err != nil {
		return resource.Accepted[resource.Subnet]{}, err
	}
	op, err := operationFrom(created, resource.ServiceNetwork)
	if err != nil {
		return resource.Accepted[resource.Subnet]{}, err
	}
	op.Action = resource.ActionCreateSubnet
	op.Targets = []resource.Ref{sub.ID.Ref()}
	return resource.Accepted[resource.Subnet]{Operation: op, Items: []resource.Subnet{sub}}, nil
}

func (c networkClient) DescribeSubnets(ctx context.Context, s backend.Scope, q resource.SubnetQuery) (resource.Page[resource.Subnet], error) {
	projectID := project(s.Account)
	want := map[string]struct{}{}
	for _, id := range q.IDs {
		want[id.String()] = struct{}{}
	}
	var items []resource.Subnet
	token := ""
	for page := 0; page < 20; page++ {
		out, err := c.vpcs.ListVpcs(ctx, &networkv1.ListVpcsRequest{
			Parent: regionParent(projectID), PageSize: 100, PageToken: token,
		})
		if err != nil {
			return resource.Page[resource.Subnet]{}, fromRPC(err)
		}
		for _, vpc := range out.GetVpcs() {
			found, err := c.listSubnetParent(ctx, vpc.GetName(), want)
			if err != nil {
				return resource.Page[resource.Subnet]{}, err
			}
			items = append(items, found...)
		}
		token = out.GetNextPageToken()
		if token == "" {
			break
		}
	}
	if len(q.IDs) == 1 && len(items) == 0 {
		return resource.Page[resource.Subnet]{}, resource.NotFound(resource.KindSubnet, q.IDs[0].String())
	}
	sortSubnets(items)
	return pageSubnets(items, q.Page)
}

func (c networkClient) listSubnetParent(ctx context.Context, parent string, want map[string]struct{}) ([]resource.Subnet, error) {
	var items []resource.Subnet
	token := ""
	for page := 0; page < 20; page++ {
		out, err := c.subnets.ListSubnets(ctx, &networkv1.ListSubnetsRequest{
			Parent: parent, PageSize: 100, PageToken: token,
		})
		if err != nil {
			return nil, fromRPC(err)
		}
		for _, item := range out.GetSubnets() {
			sub, err := subnetModel(item)
			if err != nil {
				return nil, err
			}
			if len(want) > 0 {
				if _, ok := want[sub.ID.String()]; !ok {
					continue
				}
			}
			items = append(items, sub)
		}
		token = out.GetNextPageToken()
		if token == "" {
			break
		}
	}
	return items, nil
}

func (c networkClient) GetOperation(ctx context.Context, s backend.Scope, id resource.OperationID) (resource.Operation, error) {
	out, err := c.networkOps.GetOperation(ctx, &longrunningpb.GetOperationRequest{
		Name: operationName(project(s.Account), id.Local()),
	})
	if err != nil {
		return resource.Operation{}, fromRPC(err)
	}
	op, err := operationFrom(out, resource.ServiceNetwork)
	if err != nil {
		return resource.Operation{}, err
	}
	if op.ID != id {
		return resource.Operation{}, resource.Internal(errors.New("backend returned a different operation"))
	}
	return op, nil
}

func rpcErr(op *longrunningpb.Operation, err error) error {
	if err != nil {
		return fromRPC(err)
	}
	if op.GetDone() && op.GetError() != nil {
		return fromRPC(status.ErrorProto(op.GetError()))
	}
	return nil
}

func unpackBucket(op *longrunningpb.Operation) (resource.Bucket, bool, error) {
	if op.GetResponse() == nil {
		return resource.Bucket{}, false, nil
	}
	var msg storagev1.Bucket
	if err := op.GetResponse().UnmarshalTo(&msg); err != nil {
		return resource.Bucket{}, false, resource.Internal(err)
	}
	if msg.GetName() == "" {
		return resource.Bucket{}, false, nil
	}
	b, err := bucketModel(&msg)
	return b, true, err
}

func unpackObject(op *longrunningpb.Operation) (resource.Object, bool, error) {
	if op.GetResponse() == nil {
		return resource.Object{}, false, nil
	}
	var msg storagev1.Object
	if err := op.GetResponse().UnmarshalTo(&msg); err != nil {
		return resource.Object{}, false, resource.Internal(err)
	}
	if msg.GetName() == "" {
		return resource.Object{}, false, nil
	}
	o, err := objectModel(&msg)
	return o, true, err
}

func instanceRefs(items []resource.Instance) []resource.Ref {
	out := make([]resource.Ref, 0, len(items))
	for _, item := range items {
		out = append(out, item.ID.Ref())
	}
	return out
}

func stateWanted(st resource.InstanceState, want []resource.InstanceState) bool {
	if len(want) == 0 {
		return true
	}
	for _, item := range want {
		if item == st {
			return true
		}
	}
	return false
}

func pageSize(n int) int32 {
	if n <= 0 {
		return 50
	}
	if n > 1000 {
		return 1000
	}
	return int32(n)
}

func pageInstances(items []resource.Instance, q resource.PageRequest) (resource.Page[resource.Instance], error) {
	return pageByID(items, q, func(item resource.Instance) string { return item.ID.String() })
}

func pageSubnets(items []resource.Subnet, q resource.PageRequest) (resource.Page[resource.Subnet], error) {
	return pageByID(items, q, func(item resource.Subnet) string { return item.ID.String() })
}

func pageByID[T any](items []T, q resource.PageRequest, id func(T) string) (resource.Page[T], error) {
	size := q.Size
	if size < 1 {
		size = 50
	}
	start := 0
	if q.Token != "" {
		found := false
		for i, item := range items {
			if id(item) == q.Token {
				start = i + 1
				found = true
				break
			}
		}
		if !found {
			return resource.Page[T]{}, resource.Invalid("pageToken", "unknown")
		}
	}
	end := start + size
	next := ""
	if end < len(items) {
		next = id(items[end-1])
	} else {
		end = len(items)
	}
	if start > len(items) {
		start = len(items)
	}
	return resource.Page[T]{Items: append([]T(nil), items[start:end]...), NextToken: next}, nil
}

func sortSubnets(items []resource.Subnet) {
	for i := 1; i < len(items); i++ {
		for j := i; j > 0 && items[j].ID.String() < items[j-1].ID.String(); j-- {
			items[j], items[j-1] = items[j-1], items[j]
		}
	}
}
