package iamclient

import (
	"context"
	"encoding/json"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"
)

// The directory's PolicyService and the policy fields of its users and
// groups, as vws-iam 04488bd serves them (internal/grpcapi/common.go
// attachedARNs, policyNames and checkInline): at most 10 attached policies,
// each an existing policy of the same project and none twice; inline policy
// names of at most 64 characters; inline documents that parse as a
// 2012-10-17 identity policy of at most 6144 bytes; and no aggregate inline
// size check.

type dirPolicy struct {
	id, path string
	created  time.Time
}

// dirInlineNameRE is vws-iam's ValidName, which inline policy names share
// with users and groups.
var dirInlineNameRE = regexp.MustCompile(`^[A-Za-z0-9+=,.@_-]{1,64}$`)

// seedPolicy stores the managed policy id at path in project 123456789012
// and returns its ARN.
func (d *directory) seedPolicy(id, path string) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.policies[id] = &dirPolicy{id: id, path: dirPath(path), created: time.Now().UTC()}
	return "arn:vws:iam::123456789012:policy" + dirPath(path) + id
}

// dropPolicy deletes a policy behind vws-iam's back, as a store that lost it
// would; attachments keep naming it.
func (d *directory) dropPolicy(id string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.policies, id)
}

func policyNames(project string, ids []string) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, "projects/"+project+"/policies/"+id)
	}
	return out
}

func (d *directory) GetPolicy(_ context.Context, req *iamv1.GetPolicyRequest) (*iamv1.Policy, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.enter("GetPolicy", req); err != nil {
		return nil, err
	}
	project, id, err := split(req.GetName(), "policies")
	if err != nil {
		return nil, err
	}
	p := d.policies[id]
	if p == nil || project != "123456789012" {
		return nil, awsErr(codes.NotFound, "NOT_FOUND", "NoSuchEntity")
	}
	return &iamv1.Policy{
		Name: req.GetName(), Etag: "1", Spec: &iamv1.PolicySpec{Path: p.path, DefaultVersion: "v1"},
		Status:     &iamv1.PolicyStatus{Arn: "arn:vws:iam::" + project + ":policy" + p.path + id, UniqueId: "ANPA" + id},
		CreateTime: timestamppb.New(p.created),
	}, nil
}

// racePolicies lets another writer win against a policy change of e: the
// etag moves and, with policyRacePath, the entity moves. The caller holds
// d.mu.
func (d *directory) racePolicies(e *dirEntity, paths []string) {
	if d.policyRace == 0 || !slices.ContainsFunc(paths, func(p string) bool { return strings.HasSuffix(p, "_policies") }) {
		return
	}
	d.policyRace--
	e.version++
	if d.policyRacePath != "" {
		e.path = d.policyRacePath
	}
}

// setPolicies validates and sets one policy field of e. Nothing changes on
// an error. The caller holds d.mu.
func (d *directory) setPolicies(
	project string, e *dirEntity, path string, attached []string, inline map[string]string,
) error {
	if path == "spec.inline_policies" {
		for name, doc := range inline {
			if !dirInlineNameRE.MatchString(name) {
				return awsErr(codes.InvalidArgument, "INVALID_ARGUMENT", "ValidationError")
			}
			if !dirIdentityDoc(doc) {
				return awsErr(codes.InvalidArgument, "MALFORMED_POLICY", "MalformedPolicyDocument")
			}
		}
		e.inline = maps.Clone(inline)
		return nil
	}
	if len(attached) > 10 {
		return awsErr(codes.ResourceExhausted, "QUOTA", "LimitExceeded")
	}
	ids := []string{}
	for _, n := range attached {
		p, id, err := split(n, "policies")
		if err != nil {
			return err
		}
		if p != project {
			return status.Error(codes.InvalidArgument, "policy in another project")
		}
		if d.policies[id] == nil {
			return awsErr(codes.NotFound, "NOT_FOUND", "NoSuchEntity")
		}
		if slices.Contains(ids, id) {
			return status.Error(codes.InvalidArgument, "policy attached twice")
		}
		ids = append(ids, id)
	}
	e.attached = ids
	return nil
}

// dirIdentityDoc is the part of vws-iam's policy.ParseIdentity the tests
// rely on: JSON, at most 6144 bytes, Version 2012-10-17, a Statement.
func dirIdentityDoc(doc string) bool {
	var p struct {
		Version   string          `json:"Version"`   //nolint:tagliatelle // AWS policy grammar.
		Statement json.RawMessage `json:"Statement"` //nolint:tagliatelle // AWS policy grammar.
	}
	return len(doc) <= 6144 && json.Unmarshal([]byte(doc), &p) == nil && p.Version == "2012-10-17" &&
		len(p.Statement) > 0
}
