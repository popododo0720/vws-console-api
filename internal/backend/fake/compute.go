package fake

import (
	"context"
	"errors"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

type compute struct{ w *World }

func (c compute) RunInstances(ctx context.Context, m backend.Mutation, req resource.RunInstancesRequest) (resource.Accepted[resource.Instance], error) {
	if err := ctx.Err(); err != nil {
		return resource.Accepted[resource.Instance]{}, err
	}
	c.w.mu.Lock()
	defer c.w.mu.Unlock()
	c.w.settle(c.w.now())
	if acc, ok, err := replay[resource.Accepted[resource.Instance]](c.w, m.Key, m.Fingerprint); err != nil || ok {
		return acc, err
	}
	sub, ok := c.w.sub[req.SubnetID]
	if !ok || sub.OwnerID != m.Account {
		return resource.Accepted[resource.Instance]{}, resource.NotFound(resource.KindSubnet, req.SubnetID.String())
	}
	if sub.State != resource.SubnetAvailable {
		return resource.Accepted[resource.Instance]{}, resource.Conflict(resource.KindSubnet, req.SubnetID.String(), "subnet is not available")
	}
	var key *resource.KeyPair
	if req.KeyName != "" {
		for _, k := range c.w.key {
			if k.OwnerID == m.Account && k.Name == req.KeyName {
				key = k
			}
		}
		if key == nil {
			return resource.Accepted[resource.Instance]{}, resource.NotFound(resource.KindKeyPair, req.KeyName)
		}
	}
	img, err := c.launchImage(m.Account, req.ImageID)
	if err != nil {
		return resource.Accepted[resource.Instance]{}, err
	}
	if req.RootVolumeSize, err = req.RootSizeFor(img); err != nil {
		return resource.Accepted[resource.Instance]{}, err
	}
	resID, err := resource.Mint[resource.ReservationID](c.w.entropy)
	if err != nil {
		return resource.Accepted[resource.Instance]{}, err
	}
	items := make([]resource.Instance, 0, req.Count)
	vols := make([]resource.Volume, 0, req.Count*(1+len(req.ExtraVolumes)))
	targets := make([]resource.Ref, 0, req.Count)
	seen := map[resource.InstanceID]struct{}{}
	seenVol := map[resource.VolumeID]struct{}{}
	mintVolume := func() (resource.VolumeID, error) {
		id, err := resource.Mint[resource.VolumeID](c.w.entropy)
		if err != nil {
			return resource.VolumeID{}, err
		}
		if _, exists := c.w.vol[id]; exists {
			return resource.VolumeID{}, resource.Internal(errors.New("identifier collision"))
		}
		if _, exists := seenVol[id]; exists {
			return resource.VolumeID{}, resource.Internal(errors.New("identifier collision"))
		}
		seenVol[id] = struct{}{}
		return id, nil
	}
	for i := 0; i < req.Count; i++ {
		id, err := resource.Mint[resource.InstanceID](c.w.entropy)
		if err != nil {
			return resource.Accepted[resource.Instance]{}, err
		}
		if _, exists := c.w.inst[id]; exists {
			return resource.Accepted[resource.Instance]{}, resource.Internal(errors.New("identifier collision"))
		}
		if _, exists := seen[id]; exists {
			return resource.Accepted[resource.Instance]{}, resource.Internal(errors.New("identifier collision"))
		}
		seen[id] = struct{}{}
		inst := resource.Instance{
			ID:            id,
			ReservationID: resID,
			OwnerID:       m.Account,
			State:         resource.InstancePending,
			ImageID:       req.ImageID,
			InstanceType:  req.InstanceType,
			SubnetID:      req.SubnetID,
			VpcID:         vpcOf(c.w.sub[req.SubnetID]),
			Zone:          resource.ZoneName,
			PrivateIP:     c.w.nextIP(),
			Tags:          copyTags(req.Tags),
			UserData:      req.UserData,
		}
		if key != nil {
			inst.KeyName, inst.KeyPairID = key.Name, key.ID
		}
		volID, err := mintVolume()
		if err != nil {
			return resource.Accepted[resource.Instance]{}, err
		}
		launched := c.w.now().UTC()
		iops, miBps := req.RootPerformance()
		inst.LaunchTime = launched
		inst.RootDeviceName = resource.RootDeviceName
		inst.BlockDevices = []resource.BlockDevice{{
			Device: resource.RootDeviceName, VolumeID: volID, DeleteOnTermination: !req.RootVolumeKept,
			Status: resource.AttachmentAttached, AttachTime: launched,
		}}
		vols = append(vols, resource.Volume{
			ID: volID, OwnerID: m.Account, SizeGiB: req.RootSize(), Zone: resource.ZoneName, Type: req.RootType(),
			State: resource.VolumeInUse, InstanceID: id, Device: resource.RootDeviceName,
			CreateTime: launched, AttachTime: launched, DeleteOnTermination: !req.RootVolumeKept,
			AttachState: resource.AttachmentAttached, Iops: iops, Throughput: miBps,
		})
		for _, extra := range req.ExtraVolumes {
			extraID, err := mintVolume()
			if err != nil {
				return resource.Accepted[resource.Instance]{}, err
			}
			iops, miBps := extra.Performance()
			inst.BlockDevices = append(inst.BlockDevices, resource.BlockDevice{
				Device: extra.Device, VolumeID: extraID, DeleteOnTermination: !extra.Kept,
				Status: resource.AttachmentAttached, AttachTime: launched,
			})
			vols = append(vols, resource.Volume{
				ID: extraID, OwnerID: m.Account, SizeGiB: extra.SizeGiB, Zone: resource.ZoneName,
				Type: extra.VolumeType(), State: resource.VolumeInUse, InstanceID: id, Device: extra.Device,
				CreateTime: launched, AttachTime: launched, DeleteOnTermination: !extra.Kept,
				AttachState: resource.AttachmentAttached, Iops: iops, Throughput: miBps,
			})
		}
		items = append(items, inst)
		targets = append(targets, id.Ref())
	}
	op, err := c.w.newOp(m.Account, resource.ServiceCompute, resource.ActionRunInstances, targets, func(time.Time) {
		for _, item := range items {
			if cur := c.w.inst[item.ID]; cur != nil && cur.State == resource.InstancePending {
				cur.State = resource.InstanceRunning
			}
		}
	})
	if err != nil {
		return resource.Accepted[resource.Instance]{}, err
	}
	for _, item := range items {
		stored := item
		c.w.inst[stored.ID] = &stored
	}
	for _, vol := range vols {
		stored := vol
		c.w.vol[stored.ID] = &stored
	}
	acc := resource.Accepted[resource.Instance]{Operation: op, Items: items}
	c.w.finish(m.Key, m.Fingerprint, acc)
	return acc, nil
}

func (c compute) StopInstances(ctx context.Context, m backend.Mutation, req resource.StopInstancesRequest) (resource.Accepted[resource.InstanceStateChange], error) {
	if err := ctx.Err(); err != nil {
		return resource.Accepted[resource.InstanceStateChange]{}, err
	}
	c.w.mu.Lock()
	defer c.w.mu.Unlock()
	c.w.settle(c.w.now())
	if acc, ok, err := replay[resource.Accepted[resource.InstanceStateChange]](c.w, m.Key, m.Fingerprint); err != nil || ok {
		return acc, err
	}
	type stopPlan struct {
		inst *resource.Instance
		prev resource.InstanceState
		mid  resource.InstanceState
	}
	plans := make([]stopPlan, 0, len(req.IDs))
	changes := make([]resource.InstanceStateChange, 0, len(req.IDs))
	targets := make([]resource.Ref, 0, len(req.IDs))
	for _, id := range req.IDs {
		inst, ok := c.w.inst[id]
		if !ok || inst.OwnerID != m.Account {
			return resource.Accepted[resource.InstanceStateChange]{}, resource.NotFound(resource.KindInstance, id.String())
		}
		mid, _, err := resource.NextInstanceState(resource.ActionStopInstances, inst.State)
		if err != nil {
			return resource.Accepted[resource.InstanceStateChange]{}, err
		}
		plans = append(plans, stopPlan{inst: inst, prev: inst.State, mid: mid})
		changes = append(changes, resource.InstanceStateChange{
			ID: id, OwnerID: inst.OwnerID, Previous: inst.State, Current: mid,
		})
		targets = append(targets, id.Ref())
	}
	for _, plan := range plans {
		plan.inst.State = plan.mid
	}
	op, err := c.w.newOp(m.Account, resource.ServiceCompute, resource.ActionStopInstances, targets, func(time.Time) {
		for _, ch := range changes {
			inst := c.w.inst[ch.ID]
			if inst == nil {
				continue
			}
			_, settled, err := resource.NextInstanceState(resource.ActionStopInstances, ch.Previous)
			if err != nil {
				continue
			}
			if inst.State == ch.Current {
				inst.State = settled
			}
		}
	})
	if err != nil {
		for _, plan := range plans {
			if plan.inst.State == plan.mid {
				plan.inst.State = plan.prev
			}
		}
		return resource.Accepted[resource.InstanceStateChange]{}, err
	}
	acc := resource.Accepted[resource.InstanceStateChange]{Operation: op, Items: changes}
	c.w.finish(m.Key, m.Fingerprint, acc)
	return acc, nil
}

func (c compute) DescribeInstances(ctx context.Context, s backend.Scope, q resource.InstanceQuery) (resource.Page[resource.Instance], error) {
	if err := ctx.Err(); err != nil {
		return resource.Page[resource.Instance]{}, err
	}
	c.w.mu.Lock()
	defer c.w.mu.Unlock()
	c.w.settle(c.w.now())
	wantID := map[resource.InstanceID]struct{}{}
	for _, id := range q.IDs {
		wantID[id] = struct{}{}
	}
	wantState := map[resource.InstanceState]struct{}{}
	for _, st := range q.States {
		wantState[st] = struct{}{}
	}
	if len(q.IDs) == 1 {
		inst, ok := c.w.inst[q.IDs[0]]
		if !ok || inst.OwnerID != s.Account {
			return resource.Page[resource.Instance]{}, resource.NotFound(resource.KindInstance, q.IDs[0].String())
		}
	}
	var items []resource.Instance
	for _, inst := range c.w.inst {
		if inst.OwnerID != s.Account {
			continue
		}
		if len(wantID) > 0 {
			if _, ok := wantID[inst.ID]; !ok {
				continue
			}
		}
		if len(wantState) > 0 {
			if _, ok := wantState[inst.State]; !ok {
				continue
			}
		}
		items = append(items, *inst)
	}
	sortInstances(items)
	return page(items, q.Page)
}

func (c compute) GetOperation(ctx context.Context, s backend.Scope, id resource.OperationID) (resource.Operation, error) {
	if err := ctx.Err(); err != nil {
		return resource.Operation{}, err
	}
	c.w.mu.Lock()
	defer c.w.mu.Unlock()
	return c.w.getOp(s, id, resource.ServiceCompute)
}

func (w *World) nextIP() string {
	w.seqIP++
	n := w.seqIP
	return "10.0.0." + itoa(int(n%250+1))
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [4]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func copyTags(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func sortInstances(items []resource.Instance) {
	for i := 1; i < len(items); i++ {
		for j := i; j > 0 && items[j].ID.String() < items[j-1].ID.String(); j-- {
			items[j], items[j-1] = items[j-1], items[j]
		}
	}
}

// vpcOf is the VPC of a subnet, or empty when the subnet is unknown.
func vpcOf(sub *resource.Subnet) resource.VpcID {
	if sub == nil {
		return resource.VpcID{}
	}
	return sub.VpcID
}

// launchImage is the image account launches as id: the catalog image, or a
// seeded image the caller can read, the same visibility DescribeImages
// applies (#350).
func (c compute) launchImage(account resource.AccountID, id resource.ImageID) (resource.Image, error) {
	for _, img := range resource.KnownImages(account) {
		if img.ID == id && resource.CanLaunchImage(account, id) {
			return img, nil
		}
	}
	img, ok := c.w.img[id]
	if !ok || (img.OwnerID != account && !img.Public) {
		return resource.Image{}, resource.ImageNotFound(id)
	}
	return *img, nil
}
