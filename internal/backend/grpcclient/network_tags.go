package grpcclient

import (
	"context"
	"strings"

	"google.golang.org/protobuf/types/known/fieldmaskpb"

	networkv1 "github.com/popododo0720/vws-proto/gen/go/vws/network/v1"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// TagVpcs merges tags into each VPC with a labels-only UpdateVpc. Internal
// labels the VPC already carries stay.
func (c networkClient) TagVpcs(ctx context.Context, m backend.Mutation, req resource.TagVpcsRequest) (resource.Accepted[resource.Vpc], error) {
	projectID := project(m.Account)
	type pending struct {
		name   string
		labels map[string]string
		model  resource.Vpc
	}
	work := make([]pending, 0, len(req.IDs))
	for _, id := range req.IDs {
		name := vpcName(projectID, id.String())
		got, err := c.vpcs.GetVpc(ctx, &networkv1.GetVpcRequest{Name: name})
		if err != nil {
			return resource.Accepted[resource.Vpc]{}, fromNamedRPC(name, err)
		}
		model, err := vpcModel(got)
		if err != nil {
			return resource.Accepted[resource.Vpc]{}, err
		}
		labels, tags, err := mergedLabels(got.GetLabels(), req.Tags)
		if err != nil {
			return resource.Accepted[resource.Vpc]{}, err
		}
		model.Tags = tags
		work = append(work, pending{name: name, labels: labels, model: model})
	}
	var op resource.Operation
	items := make([]resource.Vpc, 0, len(work))
	targets := make([]resource.Ref, 0, len(work))
	for i, w := range work {
		updated, err := c.vpcs.UpdateVpc(ctx, &networkv1.UpdateVpcRequest{
			RequestId:  requestUUID(m.Key, "vpc-tags", w.name),
			UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"labels"}},
			Vpc:        &networkv1.Vpc{Name: w.name, Labels: w.labels},
		})
		if err := rpcErr(updated, err); err != nil {
			return resource.Accepted[resource.Vpc]{}, err
		}
		if i == 0 {
			if op, err = operationFrom(updated, resource.ServiceNetwork); err != nil {
				return resource.Accepted[resource.Vpc]{}, err
			}
		}
		items = append(items, w.model)
		targets = append(targets, w.model.ID.Ref())
	}
	op.Action = resource.ActionCreateTags
	op.Targets = targets
	return resource.Accepted[resource.Vpc]{Operation: op, Items: items}, nil
}

// TagSubnets merges tags into each subnet with a labels-only UpdateSubnet.
func (c networkClient) TagSubnets(ctx context.Context, m backend.Mutation, req resource.TagSubnetsRequest) (resource.Accepted[resource.Subnet], error) {
	projectID := project(m.Account)
	type pending struct {
		name   string
		labels map[string]string
		model  resource.Subnet
	}
	work := make([]pending, 0, len(req.IDs))
	for _, id := range req.IDs {
		got, err := c.findSubnet(ctx, projectID, id.String())
		if err != nil {
			return resource.Accepted[resource.Subnet]{}, err
		}
		model, err := subnetModel(got)
		if err != nil {
			return resource.Accepted[resource.Subnet]{}, err
		}
		labels, tags, err := mergedLabels(got.GetLabels(), req.Tags)
		if err != nil {
			return resource.Accepted[resource.Subnet]{}, err
		}
		model.Tags = tags
		work = append(work, pending{name: got.GetName(), labels: labels, model: model})
	}
	var op resource.Operation
	items := make([]resource.Subnet, 0, len(work))
	targets := make([]resource.Ref, 0, len(work))
	for i, w := range work {
		updated, err := c.subnets.UpdateSubnet(ctx, &networkv1.UpdateSubnetRequest{
			RequestId:  requestUUID(m.Key, "subnet-tags", w.name),
			UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"labels"}},
			Subnet:     &networkv1.Subnet{Name: w.name, Labels: w.labels},
		})
		if err := rpcErr(updated, err); err != nil {
			return resource.Accepted[resource.Subnet]{}, err
		}
		if i == 0 {
			if op, err = operationFrom(updated, resource.ServiceNetwork); err != nil {
				return resource.Accepted[resource.Subnet]{}, err
			}
		}
		items = append(items, w.model)
		targets = append(targets, w.model.ID.Ref())
	}
	op.Action = resource.ActionCreateTags
	op.Targets = targets
	return resource.Accepted[resource.Subnet]{Operation: op, Items: items}, nil
}

// findSubnet returns the subnet with this id from any of the project's VPCs.
func (c networkClient) findSubnet(ctx context.Context, projectID, id string) (*networkv1.Subnet, error) {
	token := ""
	for page := 0; page < 20; page++ {
		out, err := c.vpcs.ListVpcs(ctx, &networkv1.ListVpcsRequest{
			Parent: regionParent(projectID), PageSize: 100, PageToken: token,
		})
		if err != nil {
			return nil, fromRPC(err)
		}
		for _, vpc := range out.GetVpcs() {
			subToken := ""
			for subPage := 0; subPage < 20; subPage++ {
				subs, err := c.subnets.ListSubnets(ctx, &networkv1.ListSubnetsRequest{
					Parent: vpc.GetName(), PageSize: 100, PageToken: subToken,
				})
				if err != nil {
					return nil, fromRPC(err)
				}
				for _, sub := range subs.GetSubnets() {
					if lastSegment(sub.GetName()) == id {
						return sub, nil
					}
				}
				subToken = subs.GetNextPageToken()
				if subToken == "" {
					break
				}
			}
		}
		token = out.GetNextPageToken()
		if token == "" {
			break
		}
	}
	return nil, resource.NotFound(resource.KindSubnet, id)
}

// mergedLabels writes add over the tags stored in labels and re-encodes them,
// keeping every internal label except the old tag chunks.
func mergedLabels(labels, add map[string]string) (map[string]string, map[string]string, error) {
	tags, err := resource.MergeTags(userTags(labels), add)
	if err != nil {
		return nil, nil, err
	}
	extra := map[string]string{}
	for k, v := range labels {
		if strings.HasPrefix(k, labelPrefix) && !strings.HasPrefix(k, labelTagChunk) && k != labelNameTag {
			extra[k] = v
		}
	}
	out, err := withInternalLabels(tags, extra)
	if err != nil {
		return nil, nil, err
	}
	return out, tags, nil
}
