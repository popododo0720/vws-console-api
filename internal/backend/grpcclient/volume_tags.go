package grpcclient

import (
	"context"
	"errors"

	"google.golang.org/protobuf/types/known/fieldmaskpb"

	storagev1 "github.com/popododo0720/vws-proto/gen/go/vws/storage/v1"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// TagVolumes merges tags into each volume with a labels-only UpdateVolume.
// Internal labels the volume already carries stay. Every volume is read
// before any is changed, so an unknown id changes nothing.
func (c computeClient) TagVolumes(
	ctx context.Context, m backend.Mutation, req resource.TagVolumesRequest,
) (resource.Accepted[resource.Volume], error) {
	projectID := project(m.Account)
	type pending struct {
		name   string
		labels map[string]string
		model  resource.Volume
	}
	work := make([]pending, 0, len(req.IDs))
	for _, id := range req.IDs {
		name := volumeName(projectID, id.String())
		got, err := c.volumes.GetVolume(ctx, &storagev1.GetVolumeRequest{Name: name})
		if err != nil {
			return resource.Accepted[resource.Volume]{}, fromNamedRPC(name, err)
		}
		// Tags need no volume type, so a type this build cannot name does
		// not stop them.
		model, err := volumeModel(got)
		var unknownType *unknownVolumeTypeError
		if err != nil && !errors.As(err, &unknownType) {
			return resource.Accepted[resource.Volume]{}, err
		}
		labels, tags, err := mergedLabels(got.GetLabels(), req.Tags)
		if err != nil {
			return resource.Accepted[resource.Volume]{}, err
		}
		model.Tags = tags
		work = append(work, pending{name: name, labels: labels, model: model})
	}
	var op resource.Operation
	items := make([]resource.Volume, 0, len(work))
	targets := make([]resource.Ref, 0, len(work))
	for i, w := range work {
		updated, err := c.volumes.UpdateVolume(ctx, &storagev1.UpdateVolumeRequest{
			RequestId:  requestUUID(m.Key, "volume-tags", w.name),
			UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"labels"}},
			Volume:     &storagev1.Volume{Name: w.name, Labels: w.labels},
		})
		if err := rpcErr(updated, err); err != nil {
			return resource.Accepted[resource.Volume]{}, err
		}
		if i == 0 {
			if op, err = operationFrom(updated, resource.ServiceCompute); err != nil {
				return resource.Accepted[resource.Volume]{}, err
			}
		}
		items = append(items, w.model)
		targets = append(targets, w.model.ID.Ref())
	}
	op.Action = resource.ActionCreateTags
	op.Targets = targets
	return resource.Accepted[resource.Volume]{Operation: op, Items: items}, nil
}
