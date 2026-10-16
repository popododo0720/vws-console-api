package backend

import "github.com/popododo0720/vws-console-api/internal/resource"

// VolumeBind is the desired attachment of one volume on one instance.
type VolumeBind struct {
	VolumeID   resource.VolumeID
	InstanceID resource.InstanceID
	Device     string
	Boot       bool
}

// BindOf finds id in inst.BlockDevices.
// A boot entry has DeleteOnTermination set or uses the root device name.
func BindOf(inst resource.Instance, id resource.VolumeID) (VolumeBind, bool) {
	for _, block := range inst.BlockDevices {
		if block.VolumeID != id {
			continue
		}
		return VolumeBind{
			VolumeID: id, InstanceID: inst.ID, Device: block.Device,
			Boot: block.DeleteOnTermination || block.Device == resource.RootDeviceName,
		}, true
	}
	return VolumeBind{}, false
}

// DropBind copies inst without id.
// A missing bind is not in use. A boot bind stays: instance.proto requires one
// boot entry, so a stopped instance is the same error. EC2 would allow this
// detach after stop.
func DropBind(inst resource.Instance, id resource.VolumeID) (resource.Instance, VolumeBind, error) {
	bind, ok := BindOf(inst, id)
	if !ok {
		return resource.Instance{}, VolumeBind{}, resource.Conflict(resource.KindVolume, id.String(), "volume is not in use")
	}
	if bind.Boot {
		return resource.Instance{}, VolumeBind{}, resource.Conflict(resource.KindVolume, id.String(), "volume is the root device")
	}
	blocks := make([]resource.BlockDevice, 0, len(inst.BlockDevices)-1)
	for _, block := range inst.BlockDevices {
		if block.VolumeID != id {
			blocks = append(blocks, block)
		}
	}
	inst.BlockDevices = blocks
	return inst, bind, nil
}
