package iamclient

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"cloud.google.com/go/longrunning/autogen/longrunningpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// CreatePolicy implements iam.Admin over PolicyService.CreatePolicy. The
// request is checked as the fake checks it before anything is sent, and one
// request_id rides every retry, so a create whose response was lost is
// answered from vws-iam's stored operation instead of creating twice.
func (a STSAdmin) CreatePolicy(
	ctx context.Context, account resource.AccountID, name, path, document, description string,
) (iam.ManagedPolicy, error) {
	path, err := iam.CheckManagedPolicy(name, path, document, description)
	if err != nil {
		return iam.ManagedPolicy{}, err
	}
	op, err := retry(ctx, a.backoff, a.policies.CreatePolicy, &iamv1.CreatePolicyRequest{
		Parent: projectName(account), PolicyId: name, RequestId: newRequestID(),
		Policy: &iamv1.Policy{Spec: &iamv1.PolicySpec{Path: path, Description: description, Document: document}},
	})
	if err := policyOp(op, err, name); err != nil {
		return iam.ManagedPolicy{}, err
	}
	created := &iamv1.Policy{}
	if op.GetResponse() == nil {
		return iam.ManagedPolicy{}, resource.Internal(errors.New("vws-iam CreatePolicy returned no policy"))
	}
	if err := op.GetResponse().UnmarshalTo(created); err != nil {
		return iam.ManagedPolicy{}, resource.Internal(fmt.Errorf("decode CreatePolicy response: %w", err))
	}
	return managedFromProto(created), nil
}

// GetPolicy implements iam.Admin over PolicyService.GetPolicy. An ARN whose
// path is not the stored policy's is NoSuchEntity, as in AWS.
func (a STSAdmin) GetPolicy(ctx context.Context, account resource.AccountID, arn string) (iam.ManagedPolicy, error) {
	pol, err := a.readPolicy(ctx, account, arn)
	if err != nil {
		return iam.ManagedPolicy{}, err
	}
	return managedFromProto(pol), nil
}

// ListPolicies implements iam.Admin over PolicyService.ListPolicies: every
// page, the policies whose path starts with pathPrefix ("" is "/"), sorted
// by name. vws-iam stores customer managed policies only, so this is the
// AWS Scope=Local list.
func (a STSAdmin) ListPolicies(
	ctx context.Context, account resource.AccountID, pathPrefix string,
) ([]iam.ManagedPolicy, error) {
	if pathPrefix == "" {
		pathPrefix = "/"
	}
	out := []iam.ManagedPolicy{}
	token := ""
	for {
		resp, err := retry(ctx, a.backoff, a.policies.ListPolicies, &iamv1.ListPoliciesRequest{
			Parent: projectName(account), PageSize: 1000, PageToken: token,
		})
		if err != nil {
			return nil, authError(err)
		}
		for _, p := range resp.GetPolicies() {
			if m := managedFromProto(p); strings.HasPrefix(m.Path, pathPrefix) {
				out = append(out, m)
			}
		}
		if token = resp.GetNextPageToken(); token == "" {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// DeletePolicy implements iam.Admin over PolicyService.DeletePolicy. The
// delete carries the etag of the read that checked the ARN, so a policy
// deleted and recreated at another path in between is not removed. An
// attached policy is DeleteConflict.
func (a STSAdmin) DeletePolicy(ctx context.Context, account resource.AccountID, arn string) error {
	pol, err := a.readPolicy(ctx, account, arn)
	if err != nil {
		return err
	}
	op, err := retry(ctx, a.backoff, a.policies.DeletePolicy, &iamv1.DeletePolicyRequest{
		Name: pol.GetName(), Etag: pol.GetEtag(), RequestId: newRequestID(),
	})
	err = policyOp(op, err, lastSegment(pol.GetName()))
	if resource.CodeOf(err) == resource.CodeNotFound {
		return policyNotFound(arn)
	}
	return err
}

// readPolicy reads the policy arn names and checks that its stored ARN,
// path included, is arn.
func (a STSAdmin) readPolicy(ctx context.Context, account resource.AccountID, arn string) (*iamv1.Policy, error) {
	name, err := policyResource(account, arn)
	if err != nil {
		return nil, err
	}
	pol, err := retry(ctx, a.backoff, a.policies.GetPolicy, &iamv1.GetPolicyRequest{Name: name})
	if err != nil {
		if resource.CodeOf(authError(err)) == resource.CodeNotFound {
			return nil, policyNotFound(arn)
		}
		return nil, authError(err)
	}
	if pol.GetStatus().GetArn() != arn {
		return nil, policyNotFound(arn)
	}
	return pol, nil
}

// policyOp is the outcome of a policy mutation: the call error, or else the
// error of the finished operation, mapped by policyError.
func policyOp(op *longrunningpb.Operation, err error, name string) error {
	switch {
	case err != nil:
		return policyError(err, name)
	case op != nil && op.GetDone() && op.GetError() != nil:
		return policyError(status.ErrorProto(op.GetError()), name)
	}
	return operationResult(op)
}

// policyError maps a vws-iam CreatePolicy or DeletePolicy failure to the
// error the fake answers: a taken name is EntityAlreadyExists with the AWS
// message, an etag that moved is ConcurrentModification, and the rest
// (MalformedPolicyDocument, DeleteConflict, unavailable) is authError's.
func policyError(err error, name string) error {
	st, ok := status.FromError(err)
	if !ok {
		return err
	}
	switch st.Code() { //nolint:exhaustive // the rest is authError's.
	case codes.AlreadyExists:
		return &resource.Error{
			Code:    resource.CodeAlreadyExists,
			Message: "A policy called " + name + " already exists. Duplicate names are not allowed.",
		}
	case codes.Aborted:
		return &resource.Error{Code: resource.CodeConflict, Field: iam.ConcurrentModification, Message: st.Message()}
	}
	return authError(err)
}
