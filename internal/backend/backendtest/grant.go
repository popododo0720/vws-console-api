package backendtest

import (
	"context"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// allowAll is an authorizer that allows every request, so a test can get an
// iam.AuthorizedARN the only way the code can: from iam.Authorize.
type allowAll struct{}

func (allowAll) Authorize(context.Context, iam.Request) (iam.Decision, error) {
	return iam.Decision{Allowed: true, Reason: "backendtest"}, nil
}

// Grant is the binding iam.Authorize returns for arn when the caller is
// allowed. An arn that is not the entity's own (a forged one) is still a
// valid binding, and every bound Admin call must answer it as Changed.
func Grant(ctx context.Context, t testing.TB, arn string) iam.AuthorizedARN {
	t.Helper()
	caller := resource.Caller{Account: iamAccount(), Principal: iam.RootARN(iamAccount()), Root: true}
	want, err := iam.Authorize(ctx, allowAll{}, caller, "iam:Test", arn)
	if err != nil {
		t.Fatalf("Authorize %s: %v", arn, err)
	}
	return want
}

// UserLookup is the pre-authorization read the IAM Query surface makes to
// compute the ARN it authorizes for a user.
type UserLookup interface {
	GetUser(ctx context.Context, account resource.AccountID, name string) (iam.User, error)
}

// GroupLookup is UserLookup for a group.
type GroupLookup interface {
	GetGroup(ctx context.Context, account resource.AccountID, name string) (iam.Group, []iam.User, error)
}

// RoleLookup is UserLookup for a role.
type RoleLookup interface {
	GetRole(ctx context.Context, account resource.AccountID, name string) (iam.Role, error)
}

// EntityARN is the path-less ARN the surface authorizes for a missing entity.
func EntityARN(account resource.AccountID, kind, name string) string {
	return "arn:vws:iam::" + account.String() + ":" + kind + "/" + name
}

// UserGrant is the binding the surface would authorize for user: its current
// ARN, or the path-less one when it does not exist.
func UserGrant(
	ctx context.Context, t testing.TB, a UserLookup, account resource.AccountID, user string,
) iam.AuthorizedARN {
	t.Helper()
	u, err := a.GetUser(ctx, account, user)
	if err != nil {
		return Grant(ctx, t, EntityARN(account, "user", user))
	}
	return Grant(ctx, t, u.ARN)
}

// GroupGrant is UserGrant for a group.
func GroupGrant(
	ctx context.Context, t testing.TB, a GroupLookup, account resource.AccountID, group string,
) iam.AuthorizedARN {
	t.Helper()
	g, _, err := a.GetGroup(ctx, account, group)
	if err != nil {
		return Grant(ctx, t, EntityARN(account, "group", group))
	}
	return Grant(ctx, t, g.ARN)
}

// RoleGrant is UserGrant for a role.
func RoleGrant(
	ctx context.Context, t testing.TB, a RoleLookup, account resource.AccountID, role string,
) iam.AuthorizedARN {
	t.Helper()
	r, err := a.GetRole(ctx, account, role)
	if err != nil || r.ARN == "" {
		return Grant(ctx, t, EntityARN(account, "role", role))
	}
	return Grant(ctx, t, r.ARN)
}

// EntityLookup is the lookup of every entity kind an IAM policy attaches to.
type EntityLookup interface {
	UserLookup
	GroupLookup
	RoleLookup
}

// EntityGrant is UserGrant, GroupGrant or RoleGrant by kind.
func EntityGrant(
	ctx context.Context, t testing.TB, a EntityLookup, account resource.AccountID, kind iam.Entity, name string,
) iam.AuthorizedARN {
	t.Helper()
	switch kind {
	case iam.EntityUser:
		return UserGrant(ctx, t, a, account, name)
	case iam.EntityGroup:
		return GroupGrant(ctx, t, a, account, name)
	case iam.EntityRole:
		return RoleGrant(ctx, t, a, account, name)
	default:
		return UserGrant(ctx, t, a, account, name)
	}
}
