package iam

import (
	"context"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// testAllow allows every request, so the tests of this package get an
// AuthorizedARN from Authorize like any other caller. backendtest has the
// same helpers for the other packages; it cannot be imported here.
type testAllow struct{}

func (testAllow) Authorize(context.Context, Request) (Decision, error) {
	return Decision{Allowed: true, Reason: "test"}, nil
}

func testGrant(ctx context.Context, t testing.TB, arn string) AuthorizedARN {
	t.Helper()
	want, err := Authorize(ctx, testAllow{}, resource.Caller{Principal: "test", Root: true}, "iam:Test", arn)
	if err != nil {
		t.Fatalf("Authorize %s: %v", arn, err)
	}
	return want
}

func testEntityARN(account resource.AccountID, kind, name string) string {
	return "arn:vws:iam::" + account.String() + ":" + kind + "/" + name
}

func testUserGrant(
	ctx context.Context,
	t testing.TB,
	a Resolver,
	account resource.AccountID,
	user string,
) AuthorizedARN {
	t.Helper()
	if u, err := a.ResolveUser(ctx, account, user); err == nil {
		return testGrant(ctx, t, u.ARN)
	}
	return testGrant(ctx, t, testEntityARN(account, "user", user))
}

func testGroupGrant(
	ctx context.Context, t testing.TB, a Resolver, account resource.AccountID, group string,
) AuthorizedARN {
	t.Helper()
	if g, err := a.ResolveGroup(ctx, account, group); err == nil {
		return testGrant(ctx, t, g.ARN)
	}
	return testGrant(ctx, t, testEntityARN(account, "group", group))
}

func testRoleGrant(
	ctx context.Context,
	t testing.TB,
	a Resolver,
	account resource.AccountID,
	role string,
) AuthorizedARN {
	t.Helper()
	if r, err := a.ResolveRole(ctx, account, role); err == nil {
		return testGrant(ctx, t, r.ARN)
	}
	return testGrant(ctx, t, testEntityARN(account, "role", role))
}

func testEntityGrant(
	ctx context.Context, t testing.TB, a Resolver, account resource.AccountID, kind Entity, name string,
) AuthorizedARN {
	t.Helper()
	switch kind {
	case EntityUser:
		return testUserGrant(ctx, t, a, account, name)
	case EntityGroup:
		return testGroupGrant(ctx, t, a, account, name)
	case EntityRole:
		return testRoleGrant(ctx, t, a, account, name)
	default:
		return testUserGrant(ctx, t, a, account, name)
	}
}
