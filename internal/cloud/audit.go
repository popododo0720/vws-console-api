package cloud

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/popododo0720/vws-lib/obs"
	"github.com/popododo0720/vws-lib/obs/report"
	"go.opentelemetry.io/otel/trace"

	"github.com/popododo0720/vws-console-api/internal/audit"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

type mutationAuditKey struct{}

type mutationAudit struct {
	destination audit.Destination
	resolved    bool
}

func (s *Service) startMutation(ctx *context.Context, c resource.Caller, req any,
) func(context.Context, *resource.Operation, *error) {
	start := time.Now()
	state := &mutationAudit{destination: audit.Unknown}
	*ctx = context.WithValue(*ctx, mutationAuditKey{}, state)
	return func(ctx context.Context, op *resource.Operation, result *error) {
		s.recordMutation(ctx, state, c, req, start, op, result)
	}
}

func (s *Service) mutationCapabilities(ctx context.Context, region string) (resource.RegionCapabilities, error) {
	caps, err := s.caps.RegionCapabilities(ctx, region)
	if state, ok := ctx.Value(mutationAuditKey{}).(*mutationAudit); ok {
		state.resolved = true
		if err == nil && ctx.Err() == nil {
			switch caps.Kind {
			case resource.RegionKindProxmox:
				state.destination = audit.PVE
			case resource.RegionKindAWS:
				state.destination = audit.AWS
			}
		}
	}
	return caps, err
}

func (s *Service) recordMutation(
	ctx context.Context, state *mutationAudit, c resource.Caller, req any,
	start time.Time, op *resource.Operation, result *error,
) {
	if s.audit == nil {
		return
	}
	entry := mutationEntry(req)
	entry.RequestID = obs.RequestID(ctx)
	if span := trace.SpanContextFromContext(ctx); span.IsValid() {
		entry.TraceID = span.TraceID().String()
	}
	entry.PrincipalARN, entry.Account = c.Principal, c.Account.String()
	entry.Region = s.capabilityRegion(c.Region)
	entry.SourceIP = c.SourceIP
	if !state.resolved {
		if _, err := s.mutationCapabilities(ctx, entry.Region); err != nil {
			state.destination = audit.Unknown
		}
	}
	entry.Destination = state.destination
	entry.Result = audit.Accepted
	if *result != nil {
		entry.Result = audit.Error(resource.CodeOf(*result).String())
		if resource.CodeOf(*result) == resource.CodePermissionDenied {
			entry.Result = audit.Denied
		}
	} else if op != nil {
		entry.OperationID = op.ID.String()
		entry.ResourceIDs = nil
		for _, target := range op.Targets {
			entry.ResourceIDs = append(entry.ResourceIDs, target.ID())
		}
	}
	entry.ResourceIDs = slices.DeleteFunc(entry.ResourceIDs, func(id string) bool { return id == "" })
	entry.Latency = time.Since(start)
	if err := s.audit.Record(ctx, entry); err != nil {
		// The backend may already have committed; keep its result truthful.
		_ = report.Error(ctx, errors.New("mutation audit write failed")) //nolint:errcheck // reported; result unchanged
	}
}

func mutationEntry(req any) audit.Entry {
	if entry, ok := req.(audit.Entry); ok {
		return entry
	}
	entry := audit.Entry{Service: "ec2"}
	if action, ok := req.(interface{ Action() resource.Action }); ok {
		entry.Action = action.Action().String()
	}
	switch r := req.(type) {
	case resource.RunInstancesRequest:
		entry.ResourceIDs = []string{r.ImageID.String(), r.SubnetID.String(), auditKeyName(r.KeyName)}
		for _, nic := range r.NetworkInterfaces {
			entry.ResourceIDs = append(entry.ResourceIDs, nic.SubnetID.String())
		}
	case resource.StopInstancesRequest:
		entry.ResourceIDs = auditIDs(r.IDs...)
	case resource.StartInstancesRequest:
		entry.ResourceIDs = auditIDs(r.IDs...)
	case resource.TerminateInstancesRequest:
		entry.ResourceIDs = auditIDs(r.IDs...)
	case resource.RebootInstancesRequest:
		entry.ResourceIDs = auditIDs(r.IDs...)
	case resource.CreateTagsRequest:
		entry.ResourceIDs = auditIDs(r.IDs...)
	case resource.DeleteTagsRequest:
		entry.ResourceIDs = auditIDs(r.IDs...)
	case resource.TagVpcsRequest:
		entry.ResourceIDs = auditIDs(r.IDs...)
	case resource.UntagVpcsRequest:
		entry.ResourceIDs = auditIDs(r.IDs...)
	case resource.TagSubnetsRequest:
		entry.ResourceIDs = auditIDs(r.IDs...)
	case resource.UntagSubnetsRequest:
		entry.ResourceIDs = auditIDs(r.IDs...)
	case resource.TagVolumesRequest:
		entry.ResourceIDs = auditIDs(r.IDs...)
	case resource.UntagVolumesRequest:
		entry.ResourceIDs = auditIDs(r.IDs...)
	case resource.CreateSubnetRequest:
		entry.ResourceIDs = []string{r.VpcID.String()}
	case resource.DeleteSubnetRequest:
		entry.ResourceIDs = []string{r.ID.String()}
	case resource.DeleteVpcRequest:
		entry.ResourceIDs = []string{r.ID.String()}
	case resource.CreateVolumeRequest:
		entry.ResourceIDs = []string{r.SnapshotID.String()}
	case resource.AttachVolumeRequest:
		entry.ResourceIDs = []string{r.VolumeID.String(), r.InstanceID.String()}
	case resource.DetachVolumeRequest:
		entry.ResourceIDs = []string{r.VolumeID.String(), r.InstanceID.String()}
	case resource.DeleteVolumeRequest:
		entry.ResourceIDs = []string{r.ID.String()}
	case resource.ModifyVolumeRequest:
		entry.ResourceIDs = []string{r.ID.String()}
	case resource.CreateSnapshotRequest:
		entry.ResourceIDs = []string{r.VolumeID.String()}
	case resource.DeleteSnapshotRequest:
		entry.ResourceIDs = []string{r.ID.String()}
	case resource.RegisterImageRequest:
		entry.ResourceIDs = []string{r.SnapshotID.String()}
	case resource.CreateKeyPairRequest:
		entry.ResourceIDs = []string{auditKeyName(r.Name)}
		if r.PublicKey != "" {
			entry.Action = "ImportKeyPair"
		}
	case resource.DeleteKeyPairRequest:
		entry.ResourceIDs = []string{r.ID.String(), auditKeyName(r.Name)}
	case resource.CreateSecurityGroupRequest:
		entry.ResourceIDs = []string{r.VpcID.String()}
	case resource.DeleteSecurityGroupRequest:
		entry.ResourceIDs = []string{r.ID.String()}
	case resource.AuthorizeSecurityGroupIngressRequest:
		entry.ResourceIDs = []string{r.ID.String()}
	case resource.RevokeSecurityGroupIngressRequest:
		entry.ResourceIDs = []string{r.ID.String()}
	case resource.ReleaseAddressRequest:
		entry.ResourceIDs = []string{r.ID.String()}
	case resource.AssociateAddressRequest:
		entry.ResourceIDs = []string{r.ID.String(), r.InstanceID.String()}
	case resource.DisassociateAddressRequest:
		if !r.ID.IsZero() {
			entry.ResourceIDs = []string{resource.AssociationID(r.ID)}
		}
	}
	return entry
}

func auditKeyName(name string) string {
	r, err := (resource.CreateKeyPairRequest{Name: name}).Normalize()
	if err != nil || strings.ContainsFunc(r.Name, unicode.IsControl) {
		return ""
	}
	return r.Name
}

func auditObjectID(bucket resource.BucketName, key resource.ObjectKey) []string {
	if bucket.IsZero() || key.IsZero() {
		return nil
	}
	return []string{bucket.String() + "/" + key.String()}
}

func auditIDs[T fmt.Stringer](ids ...T) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, id.String())
	}
	return out
}
