package iamclient

import (
	"context"
	"slices"
	"sort"
	"strconv"
	"time"

	"cloud.google.com/go/longrunning/autogen/longrunningpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"
)

// The directory's managed policy CRUD, as vws-iam 00ea64d serves it
// (internal/grpcapi/policies.go): CreatePolicy parses the document as an
// identity policy and refuses a taken name, request_id replays, ListPolicies
// pages by name, and DeletePolicy checks the etag and refuses a policy any
// user or group attaches (FAILED_PRECONDITION, aws_code DeleteConflict).

// policyProto is the stored policy p of project as vws-iam returns it. The
// caller holds d.mu.
func (d *directory) policyProto(project string, p *dirPolicy) *iamv1.Policy {
	attached := 0
	for _, es := range []map[string]*dirEntity{d.users, d.groups} {
		for _, e := range es {
			if slices.Contains(e.attached, p.id) {
				attached++
			}
		}
	}
	return &iamv1.Policy{
		Name: "projects/" + project + "/policies/" + p.id, Etag: strconv.Itoa(p.version + 1),
		Spec: &iamv1.PolicySpec{Path: p.path, Description: p.description, DefaultVersion: "v1"},
		Status: &iamv1.PolicyStatus{
			Arn: "arn:vws:iam::" + project + ":policy" + p.path + p.id, UniqueId: "ANPA" + p.id,
			AttachmentCount: int32(attached), //nolint:gosec // test sizes are tiny.
		},
		CreateTime: timestamppb.New(p.created),
	}
}

func (d *directory) CreatePolicy(_ context.Context, req *iamv1.CreatePolicyRequest) (*longrunningpb.Operation, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.enter("CreatePolicy", req); err != nil {
		return nil, err
	}
	if op, found, err := d.replay("CreatePolicy", req.GetRequestId(), req); found {
		return op, err
	}
	if req.GetParent() != "projects/123456789012" || !dirNameRE.MatchString(req.GetPolicyId()) {
		return nil, status.Error(codes.InvalidArgument, "bad policy id")
	}
	spec := req.GetPolicy().GetSpec()
	if !dirIdentityDoc(spec.GetDocument()) {
		return nil, awsErr(codes.InvalidArgument, "MALFORMED_POLICY", "MalformedPolicyDocument")
	}
	if err := checkPathArg(spec.GetPath()); err != nil {
		return nil, err
	}
	if d.policies[req.GetPolicyId()] != nil {
		return nil, awsErr(codes.AlreadyExists, "ALREADY_EXISTS", "EntityAlreadyExists")
	}
	p := &dirPolicy{id: req.GetPolicyId(), path: dirPath(spec.GetPath()), description: spec.GetDescription(), created: time.Now().UTC()}
	d.policies[p.id] = p
	d.seq++
	return d.done("CreatePolicy", req.GetRequestId(), req, d.policyProto("123456789012", p))
}

func (d *directory) ListPolicies(_ context.Context, req *iamv1.ListPoliciesRequest) (*iamv1.ListPoliciesResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.enter("ListPolicies", req); err != nil {
		return nil, err
	}
	if req.GetParent() != "projects/123456789012" {
		return &iamv1.ListPoliciesResponse{}, nil
	}
	ids := []string{}
	for id := range d.policies {
		if id > req.GetPageToken() {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	n := min(int(req.GetPageSize()), 1000, d.maxPage)
	if n <= 0 {
		n = 50
	}
	out := &iamv1.ListPoliciesResponse{}
	if len(ids) > n {
		ids = ids[:n]
		out.NextPageToken = ids[n-1]
	}
	for _, id := range ids {
		out.Policies = append(out.Policies, d.policyProto("123456789012", d.policies[id]))
	}
	return out, nil
}

func (d *directory) DeletePolicy(_ context.Context, req *iamv1.DeletePolicyRequest) (*longrunningpb.Operation, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.enter("DeletePolicy", req); err != nil {
		return nil, err
	}
	if op, found, err := d.replay("DeletePolicy", req.GetRequestId(), req); found {
		return op, err
	}
	project, id, err := split(req.GetName(), "policies")
	if err != nil {
		return nil, err
	}
	p := d.policies[id]
	if p == nil || project != "123456789012" {
		return nil, awsErr(codes.NotFound, "NOT_FOUND", "NoSuchEntity")
	}
	if d.onDeletePolicy != nil {
		d.onDeletePolicy(d)
	}
	resp := d.policyProto(project, p)
	if req.GetEtag() != "" && req.GetEtag() != resp.GetEtag() {
		return nil, awsErr(codes.Aborted, "ABORTED", "ConcurrentModification")
	}
	if resp.GetStatus().GetAttachmentCount() > 0 {
		return nil, awsErr(codes.FailedPrecondition, "DELETE_CONFLICT", "DeleteConflict")
	}
	delete(d.policies, id)
	d.seq++
	return d.done("DeletePolicy", req.GetRequestId(), req, resp)
}
