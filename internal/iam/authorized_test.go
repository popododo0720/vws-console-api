package iam_test

import (
	"context"
	"errors"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

type decide struct {
	d   iam.Decision
	err error
}

func (a decide) Authorize(context.Context, iam.Request) (iam.Decision, error) { return a.d, a.err }

// #342: iam.Authorize is the only way to an AuthorizedPrincipal. It returns one for
// the authorized ARN only after an allowed decision; a deny, an authorizer
// error or no authorizer return the zero value, which Require and Bind refuse
// as an internal error, even against an empty ARN.
func TestAuthorizedPrincipal(t *testing.T) {
	ctx := context.Background()
	caller := resource.Caller{Principal: "arn:vws:iam::123456789012:user/admin"}
	const arn = "arn:vws:iam::123456789012:user/ops/alice"

	want, err := iam.Authorize(ctx, decide{d: iam.Decision{Allowed: true}}, caller, "iam:GetUser", arn)
	if err != nil || want.IsZero() || want.String() != arn {
		t.Fatalf("allowed: %q (zero %v), %v", want.String(), want.IsZero(), err)
	}
	if err := want.Require(); err != nil {
		t.Errorf("Require of an authorized ARN: %v", err)
	}
	if err := want.Bind(arn, iam.UserChanged); err != nil {
		t.Errorf("Bind to the authorized ARN: %v", err)
	}
	err = want.Bind("arn:vws:iam::123456789012:user/denied/alice", iam.UserChanged)
	if !iam.IsChanged(err) || resource.AsError(err).Message != iam.UserChanged {
		t.Errorf("Bind to a moved ARN: %v", err)
	}

	for name, a := range map[string]iam.Authorizer{
		"deny":     decide{d: iam.Decision{Allowed: false}},
		"error":    decide{err: errors.New("down")},
		"no authz": nil,
	} {
		got, err := iam.Authorize(ctx, a, caller, "iam:GetUser", arn)
		if err == nil || !got.IsZero() {
			t.Errorf("%s: %q, %v; want the zero value and an error", name, got.String(), err)
		}
	}

	var zero iam.AuthorizedPrincipal
	for what, err := range map[string]error{
		"Require":       zero.Require(),
		"Bind":          zero.Bind(arn, iam.UserChanged),
		"Bind to empty": zero.Bind("", iam.UserChanged),
	} {
		if resource.CodeOf(err) != resource.CodeInternal || iam.IsChanged(err) {
			t.Errorf("zero %s: %v, want internal", what, err)
		}
	}
}
