package iamclient

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"sort"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// The managed and inline policies of a user or group over vws-iam (#314).
//
// They are UserSpec and GroupSpec fields: attached_policies, the resource
// names of the managed policies, and inline_policies, a map from policy name
// to document. A change reads the user or group, computes the new field and
// writes only that field under the etag it read with a fresh request_id,
// which vws-iam replays, so a retry on UNAVAILABLE applies it once. When
// another writer moved the etag, it reads again, up to membershipAttempts
// times, as group membership changes do. Every read, the first included,
// must find the entity at the AuthorizedPrincipal: one moved since the caller was
// authorized is a ConcurrentModification, and nothing is written. A zero
// AuthorizedPrincipal is Internal before anything is sent.
//
// The AWS rules are checked here, before vws-iam's: the PoliciesPerUser and
// PoliciesPerGroup quotas, the policy grammar and the aggregate inline
// size. vws-iam also limits inline policy names to 64 characters, where AWS
// allows 128, so a longer name is refused without a call. The role policy
// calls are not mapped yet.

// maxVWSInlineName is the longest inline policy name vws-iam stores.
const maxVWSInlineName = 64

// policyAction is the AWS action name of a policy call on kind, such as
// AttachUserPolicy or ListAttachedGroupPolicies.
func policyAction(prefix string, kind iam.Entity, suffix string) string {
	word := "User"
	switch kind {
	case iam.EntityGroup:
		word = "Group"
	case iam.EntityRole:
		word = "Role"
	case iam.EntityUser:
	}
	return prefix + word + suffix
}

// observePolicy is observe for a policy call: the span also carries the
// policy name or ARN, and a mutation leaves one log record with them. The
// policy document never reaches the span or the log.
func (a STSAdmin) observePolicy(
	ctx context.Context, action string, mutation bool, account resource.AccountID, kind iam.Entity,
	name, policyName, policyARN string,
) (context.Context, func(error)) {
	start := time.Now()
	user, group := name, ""
	if kind == iam.EntityGroup {
		user, group = "", name
	}
	ctx, end := a.observe(ctx, action, false, account, user, group)
	span := trace.SpanFromContext(ctx)
	if policyName != "" {
		span.SetAttributes(attribute.String("vws.iam.policy_name", policyName))
	}
	if policyARN != "" {
		span.SetAttributes(attribute.String("vws.iam.policy_arn", policyARN))
	}
	return ctx, func(err error) {
		end(err)
		if !mutation {
			return
		}
		outcome := "ok"
		if err != nil {
			outcome = resource.CodeOf(err).String()
		}
		level := slog.LevelInfo
		logAttrs := []slog.Attr{
			slog.String("action", action),
			slog.String("user_name", user), slog.String("group_name", group),
			slog.String("policy_name", policyName),
			slog.String("outcome", outcome), slog.Duration("elapsed", time.Since(start)),
		}
		if c := resource.CodeOf(err); c == resource.CodeUnavailable || c == resource.CodeInternal {
			level = slog.LevelWarn
			logAttrs = append(logAttrs, slog.String("error", err.Error()))
		}
		a.logger().LogAttrs(ctx, level, "vws-iam user or group policy change", logAttrs...)
	}
}

// policyHolder is the policy part of a vws-iam user or group as read for a
// change.
type policyHolder struct {
	resourceName, etag string
	attached           []string
	inline             map[string]string
}

// policyChange is the new attached_policies or inline_policies of a holder;
// a zero one writes nothing.
type policyChange struct {
	mask     string
	attached []string
	inline   map[string]string
}

func entityWord(kind iam.Entity) string {
	if kind == iam.EntityGroup {
		return "group"
	}
	return "user"
}

// readHolder reads the user or group name of kind and checks it is still at
// the authorized ARN.
func (a STSAdmin) readHolder(
	ctx context.Context, account resource.AccountID, kind iam.Entity, name string, want iam.AuthorizedPrincipal,
) (policyHolder, error) {
	if !entityName(name) {
		return policyHolder{}, entityNotFound(entityWord(kind), name)
	}
	var h policyHolder
	var arn string
	if kind == iam.EntityGroup {
		raw, g, err := a.rawGroup(ctx, account, name)
		if err != nil {
			return policyHolder{}, err
		}
		h = policyHolder{raw.GetName(), raw.GetEtag(), raw.GetSpec().GetAttachedPolicies(), raw.GetSpec().GetInlinePolicies()}
		arn = g.ARN
	} else {
		raw, u, err := a.rawUser(ctx, account, name)
		if err != nil {
			return policyHolder{}, err
		}
		h = policyHolder{raw.GetName(), raw.GetEtag(), raw.GetSpec().GetAttachedPolicies(), raw.GetSpec().GetInlinePolicies()}
		arn = u.ARN
	}
	if err := want.Bind(arn, changedMessage(kind)); err != nil {
		return policyHolder{}, err
	}
	return h, nil
}

// changedMessage is the ConcurrentModification message of a policy call on
// kind.
func changedMessage(kind iam.Entity) string {
	switch kind {
	case iam.EntityGroup:
		return iam.GroupChanged
	case iam.EntityRole:
		return iam.RoleChanged
	case iam.EntityUser:
	}
	return iam.UserChanged
}

// writeHolder writes one policy field of h under its etag.
func (a STSAdmin) writeHolder(ctx context.Context, kind iam.Entity, name string, h policyHolder, c policyChange) error {
	mask := &fieldmaskpb.FieldMask{Paths: []string{c.mask}}
	var err error
	if kind == iam.EntityGroup {
		spec := &iamv1.GroupSpec{AttachedPolicies: c.attached, InlinePolicies: c.inline}
		op, callErr := retry(ctx, a.backoff, a.groups.UpdateGroup, &iamv1.UpdateGroupRequest{
			Group: &iamv1.Group{Name: h.resourceName, Etag: h.etag, Spec: spec}, UpdateMask: mask, RequestId: newRequestID(),
		})
		err = callErr
		if err == nil {
			return opError(op, "group", name)
		}
	} else {
		spec := &iamv1.UserSpec{AttachedPolicies: c.attached, InlinePolicies: c.inline}
		op, callErr := retry(ctx, a.backoff, a.users.UpdateUser, &iamv1.UpdateUserRequest{
			User: &iamv1.User{Name: h.resourceName, Etag: h.etag, Spec: spec}, UpdateMask: mask, RequestId: newRequestID(),
		})
		err = callErr
		if err == nil {
			return opError(op, "user", name)
		}
	}
	return entityError(err, entityWord(kind), name)
}

// changePolicies reads the holder, asks change for the new field and writes
// it, reading again when another writer won, as changeMembers does.
func (a STSAdmin) changePolicies(
	ctx context.Context, account resource.AccountID, kind iam.Entity, name string, want iam.AuthorizedPrincipal,
	change func(ctx context.Context, h policyHolder) (policyChange, error),
) error {
	ctx, cancel := context.WithTimeout(ctx, OperationTimeout)
	defer cancel()
	var lost error
	for range membershipAttempts {
		h, err := a.readHolder(ctx, account, kind, name, want)
		if err != nil {
			return err
		}
		c, err := change(ctx, h)
		if err != nil || c.mask == "" {
			return err
		}
		err = a.writeHolder(ctx, kind, name, h, c)
		switch resource.CodeOf(err) { //nolint:exhaustive // only a lost race is read again.
		case resource.CodeConflict, resource.CodeNotFound:
			lost = err
			continue
		}
		return err
	}
	return backendUnavailable(fmt.Errorf("%s %s kept changing: %w", entityWord(kind), name, lost))
}

func attachedIndex(attached []string, resourceName string) int {
	return slices.IndexFunc(attached, func(p string) bool { return strings.EqualFold(p, resourceName) })
}

// AttachPolicy implements iam.Admin on spec.attached_policies. Attaching an
// attached policy is a no-op; one more than MaxAttachedPolicies is
// LimitExceeded.
func (a STSAdmin) AttachPolicy(
	ctx context.Context, account resource.AccountID, kind iam.Entity, name, arn string, want iam.AuthorizedPrincipal,
) (err error) {
	if err := want.Require(); err != nil {
		return err
	}
	if kind == iam.EntityRole {
		return notServed("AttachRolePolicy")
	}
	ctx, end := a.observePolicy(ctx, policyAction("Attach", kind, "Policy"), true, account, kind, name, "", arn)
	defer func() { end(err) }()
	change := func(ctx context.Context, h policyHolder) (policyChange, error) {
		p, err := a.policyFor(ctx, account, arn)
		if err != nil {
			return policyChange{}, err
		}
		if attachedIndex(h.attached, p) >= 0 {
			return policyChange{}, nil
		}
		if len(h.attached) >= iam.MaxAttachedPolicies {
			return policyChange{}, iam.AttachedQuotaExceeded(kind)
		}
		return policyChange{mask: "spec.attached_policies", attached: append(slices.Clone(h.attached), p)}, nil
	}
	return a.changePolicies(ctx, account, kind, name, want, change)
}

// DetachPolicy implements iam.Admin on spec.attached_policies. A policy that
// is not attached is NoSuchEntity, as in AWS.
func (a STSAdmin) DetachPolicy(
	ctx context.Context, account resource.AccountID, kind iam.Entity, name, arn string, want iam.AuthorizedPrincipal,
) (err error) {
	if err := want.Require(); err != nil {
		return err
	}
	if kind == iam.EntityRole {
		return notServed("DetachRolePolicy")
	}
	ctx, end := a.observePolicy(ctx, policyAction("Detach", kind, "Policy"), true, account, kind, name, "", arn)
	defer func() { end(err) }()
	change := func(ctx context.Context, h policyHolder) (policyChange, error) {
		p, err := a.policyFor(ctx, account, arn)
		if err != nil {
			return policyChange{}, err
		}
		i := attachedIndex(h.attached, p)
		if i < 0 {
			return policyChange{}, iam.PolicyNotAttached(arn)
		}
		return policyChange{mask: "spec.attached_policies", attached: slices.Delete(slices.Clone(h.attached), i, i+1)}, nil
	}
	return a.changePolicies(ctx, account, kind, name, want, change)
}

// ListAttachedPolicies implements iam.Admin: the attached policies of the
// user or group, each read with PolicyService.GetPolicy, sorted by name. A
// policy vws-iam no longer has is left out. The AuthorizedPrincipal must be
// the entity's ARN when it is read before the policies and again after
// them, as in ListAccessKeys.
func (a STSAdmin) ListAttachedPolicies(
	ctx context.Context, account resource.AccountID, kind iam.Entity, name string, want iam.AuthorizedPrincipal,
) (out []iam.ManagedPolicy, err error) {
	if err := want.Require(); err != nil {
		return nil, err
	}
	if kind == iam.EntityRole {
		return nil, notServed("ListAttachedRolePolicies")
	}
	ctx, end := a.observePolicy(ctx, policyAction("ListAttached", kind, "Policies"), false, account, kind, name, "", "")
	defer func() { end(err) }()
	ctx, cancel := context.WithTimeout(ctx, OperationTimeout)
	defer cancel()
	h, err := a.readHolder(ctx, account, kind, name, want)
	if err != nil {
		return nil, err
	}
	out = []iam.ManagedPolicy{}
	prefix := "arn:vws:iam::" + account.String() + ":policy/"
	for _, resourceName := range h.attached {
		p, err := retry(ctx, a.backoff, a.policies.GetPolicy, &iamv1.GetPolicyRequest{Name: resourceName})
		if err != nil {
			if err = authError(err); resource.CodeOf(err) == resource.CodeNotFound {
				continue
			}
			return nil, err
		}
		if !strings.HasPrefix(p.GetStatus().GetArn(), prefix) {
			return nil, resource.Internal(errors.New("vws-iam returned a policy outside the caller's account"))
		}
		out = append(out, managedFromProto(p))
	}
	if _, err := a.readHolder(ctx, account, kind, name, want); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func managedFromProto(p *iamv1.Policy) iam.ManagedPolicy {
	m := iam.ManagedPolicy{
		Name: lastSegment(p.GetName()), Path: p.GetSpec().GetPath(), ID: p.GetStatus().GetUniqueId(),
		ARN: p.GetStatus().GetArn(), Description: p.GetSpec().GetDescription(),
		DefaultVersion: p.GetSpec().GetDefaultVersion(), AttachmentCount: int(p.GetStatus().GetAttachmentCount()),
	}
	if m.Path == "" {
		m.Path = "/"
	}
	if t := p.GetCreateTime(); t != nil {
		m.Created = t.AsTime()
	}
	if t := p.GetUpdateTime(); t != nil {
		m.Updated = t.AsTime()
	}
	return m
}

// PutInlinePolicy implements iam.Admin on spec.inline_policies: it adds or
// replaces the policy of that name. The new documents of the entity must fit
// the AWS aggregate inline size. Putting the same document again writes
// nothing.
func (a STSAdmin) PutInlinePolicy(
	ctx context.Context, account resource.AccountID, kind iam.Entity, name, policy, document string,
	want iam.AuthorizedPrincipal,
) (err error) {
	if err := want.Require(); err != nil {
		return err
	}
	if kind == iam.EntityRole {
		return notServed("PutRolePolicy")
	}
	ctx, end := a.observePolicy(ctx, policyAction("Put", kind, "Policy"), true, account, kind, name, policy, "")
	defer func() { end(err) }()
	if err := iam.CheckInlinePolicyName(policy); err != nil {
		return err
	}
	if len(policy) > maxVWSInlineName {
		return resource.Invalid("policyName", "vws-iam accepts inline policy names of at most 64 characters")
	}
	if err := iam.ValidateIdentityPolicy(document); err != nil {
		return err
	}
	change := func(_ context.Context, h policyHolder) (policyChange, error) {
		if doc, ok := h.inline[policy]; ok && doc == document {
			return policyChange{}, nil
		}
		next := maps.Clone(h.inline)
		if next == nil {
			next = map[string]string{}
		}
		next[policy] = document
		if err := iam.CheckInlinePolicySize(kind, name, next); err != nil {
			return policyChange{}, err
		}
		return policyChange{mask: "spec.inline_policies", inline: next}, nil
	}
	return a.changePolicies(ctx, account, kind, name, want, change)
}

// GetInlinePolicy implements iam.Admin: the document as stored.
func (a STSAdmin) GetInlinePolicy(
	ctx context.Context, account resource.AccountID, kind iam.Entity, name, policy string, want iam.AuthorizedPrincipal,
) (doc string, err error) {
	if err := want.Require(); err != nil {
		return "", err
	}
	if kind == iam.EntityRole {
		return "", notServed("GetRolePolicy")
	}
	ctx, end := a.observePolicy(ctx, policyAction("Get", kind, "Policy"), false, account, kind, name, policy, "")
	defer func() { end(err) }()
	h, err := a.readHolder(ctx, account, kind, name, want)
	if err != nil {
		return "", err
	}
	doc, ok := h.inline[policy]
	if !ok {
		return "", iam.InlinePolicyNotFound(kind, policy)
	}
	return doc, nil
}

// DeleteInlinePolicy implements iam.Admin on spec.inline_policies. A policy
// the entity does not have is NoSuchEntity.
func (a STSAdmin) DeleteInlinePolicy(
	ctx context.Context, account resource.AccountID, kind iam.Entity, name, policy string, want iam.AuthorizedPrincipal,
) (err error) {
	if err := want.Require(); err != nil {
		return err
	}
	if kind == iam.EntityRole {
		return notServed("DeleteRolePolicy")
	}
	ctx, end := a.observePolicy(ctx, policyAction("Delete", kind, "Policy"), true, account, kind, name, policy, "")
	defer func() { end(err) }()
	change := func(_ context.Context, h policyHolder) (policyChange, error) {
		if _, ok := h.inline[policy]; !ok {
			return policyChange{}, iam.InlinePolicyNotFound(kind, policy)
		}
		next := maps.Clone(h.inline)
		delete(next, policy)
		return policyChange{mask: "spec.inline_policies", inline: next}, nil
	}
	return a.changePolicies(ctx, account, kind, name, want, change)
}

// ListInlinePolicies implements iam.Admin: the inline policy names, sorted.
func (a STSAdmin) ListInlinePolicies(
	ctx context.Context, account resource.AccountID, kind iam.Entity, name string, want iam.AuthorizedPrincipal,
) (out []string, err error) {
	if err := want.Require(); err != nil {
		return nil, err
	}
	if kind == iam.EntityRole {
		return nil, notServed("ListRolePolicies")
	}
	ctx, end := a.observePolicy(ctx, policyAction("List", kind, "Policies"), false, account, kind, name, "", "")
	defer func() { end(err) }()
	h, err := a.readHolder(ctx, account, kind, name, want)
	if err != nil {
		return nil, err
	}
	out = slices.Sorted(maps.Keys(h.inline))
	if out == nil {
		out = []string{}
	}
	return out, nil
}
