package backendtest

import (
	"context"
	"regexp"
	"slices"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// IAMAccessKeys runs the #314 bundle 2 contract of the iam.Directory access key
// calls, which the in-memory fake and the vws-iam client must answer alike.
// Each row starts from the IAMUsersAndGroups seed: alice (/ops/), bob (/eng/)
// and devs (/team/, member alice), none of them with a key.
func IAMAccessKeys(t *testing.T, newAdmin IAMAdminHarness) {
	t.Helper()
	for _, row := range iamAccessKeyRows() {
		t.Run(row.name, func(t *testing.T) {
			ctx := context.Background()
			a := newAdmin(t)
			seedIAM(ctx, t, a)
			row.run(ctx, t, a)
		})
	}
}

// accessKeyIDShape is an AWS long-term access key id: AKIA and 16 more.
var accessKeyIDShape = regexp.MustCompile(`^AKIA[A-Z2-7]{16}$`)

func keyIDs(ks []iam.AccessKeyMeta) []string {
	out := []string{}
	for _, k := range ks {
		out = append(out, k.AccessKeyID)
	}
	return out
}

func wantKeys(ctx context.Context, t *testing.T, a iam.Directory, user string, want ...string) []iam.AccessKeyMeta {
	t.Helper()
	ks, err := a.ListAccessKeys(ctx, iamAccount(), user, UserGrant(ctx, t, a, iamAccount(), user))
	wantOK(t, "ListAccessKeys "+user, err)
	slices.Sort(want)
	if want == nil {
		want = []string{}
	}
	if got := keyIDs(ks); !slices.Equal(got, want) {
		t.Fatalf("keys of %s: %q, want %q", user, got, want)
	}
	return ks
}

// iamAccessKeyRows are the #314 bundle 2 rows.
func iamAccessKeyRows() []iamRow {
	return []iamRow{
		{"CreateAccessKey returns an active key and its secret once", func(
			ctx context.Context, t *testing.T, a iam.Directory,
		) {
			before := time.Now().Add(-time.Minute)
			k, err := a.CreateAccessKey(ctx, iamAccount(), "bob", UserGrant(ctx, t, a, iamAccount(), "bob"))
			wantOK(t, "CreateAccessKey", err)
			if k.UserName != "bob" || !accessKeyIDShape.MatchString(k.AccessKeyID) || k.Status != "Active" ||
				len(k.Secret) != 40 || k.Created.Before(before) || k.Created.After(time.Now().Add(time.Minute)) {
				t.Fatalf("CreateAccessKey: %s %s %s secret of %d, created %v",
					k.UserName, k.AccessKeyID, k.Status, len(k.Secret), k.Created)
			}
			ks := wantKeys(ctx, t, a, "bob", k.AccessKeyID)
			if ks[0].UserName != "bob" || ks[0].Status != "Active" || !ks[0].Created.Equal(k.Created) {
				t.Fatalf("ListAccessKeys row %+v, created %v", ks[0], k.Created)
			}
			wantKeys(ctx, t, a, "alice")
		}},
		{"a third key is LimitExceeded and the two stay", func(ctx context.Context, t *testing.T, a iam.Directory) {
			k1, err := a.CreateAccessKey(ctx, iamAccount(), "bob", UserGrant(ctx, t, a, iamAccount(), "bob"))
			wantOK(t, "CreateAccessKey 1", err)
			k2, err := a.CreateAccessKey(ctx, iamAccount(), "bob", UserGrant(ctx, t, a, iamAccount(), "bob"))
			wantOK(t, "CreateAccessKey 2", err)
			if k1.AccessKeyID == k2.AccessKeyID || k1.Secret == k2.Secret {
				t.Fatal("two keys share an id or a secret")
			}
			_, err = a.CreateAccessKey(ctx, iamAccount(), "bob", UserGrant(ctx, t, a, iamAccount(), "bob"))
			wantErr(t, "CreateAccessKey 3", err, resource.CodeResourceExhausted,
				"Cannot exceed quota for AccessKeysPerUser: 2")
			wantKeys(ctx, t, a, "bob", k1.AccessKeyID, k2.AccessKeyID)
			_, err = a.CreateAccessKey(ctx, iamAccount(), "alice", UserGrant(ctx, t, a, iamAccount(), "alice"))
			wantOK(t, "the quota is per user", err)
		}},
		{"a missing user is NoSuchEntity", func(ctx context.Context, t *testing.T, a iam.Directory) {
			_, err := a.CreateAccessKey(ctx, iamAccount(), "ghost", UserGrant(ctx, t, a, iamAccount(), "ghost"))
			wantErr(t, "CreateAccessKey", err, resource.CodeNotFound, "The user with name ghost cannot be found.")
			_, err = a.ListAccessKeys(ctx, iamAccount(), "ghost", UserGrant(ctx, t, a, iamAccount(), "ghost"))
			wantErr(t, "ListAccessKeys", err, resource.CodeNotFound, "The user with name ghost cannot be found.")
			err = a.DeleteAccessKey(
				ctx, iamAccount(), "ghost", "AKIAAAAAAAAAAAAAAAAA", UserGrant(ctx, t, a, iamAccount(), "ghost"),
			)
			wantErr(t, "DeleteAccessKey", err, resource.CodeNotFound, "The user with name ghost cannot be found.")
		}},
		{"DeleteAccessKey deletes; a missing or another user's key is NoSuchEntity", func(
			ctx context.Context, t *testing.T, a iam.Directory,
		) {
			bobs, err := a.CreateAccessKey(ctx, iamAccount(), "bob", UserGrant(ctx, t, a, iamAccount(), "bob"))
			wantOK(t, "CreateAccessKey bob", err)
			alices, err := a.CreateAccessKey(ctx, iamAccount(), "alice", UserGrant(ctx, t, a, iamAccount(), "alice"))
			wantOK(t, "CreateAccessKey alice", err)
			err = a.DeleteAccessKey(ctx, iamAccount(), "alice", bobs.AccessKeyID, UserGrant(ctx, t, a, iamAccount(), "alice"))
			wantErr(t, "DeleteAccessKey of bob's key as alice", err, resource.CodeNotFound,
				"The Access Key with name "+bobs.AccessKeyID+" cannot be found.")
			wantKeys(ctx, t, a, "bob", bobs.AccessKeyID)
			wantOK(
				t,
				"DeleteAccessKey",
				a.DeleteAccessKey(ctx, iamAccount(), "bob", bobs.AccessKeyID, UserGrant(ctx, t, a, iamAccount(), "bob")),
			)
			wantKeys(ctx, t, a, "bob")
			err = a.DeleteAccessKey(ctx, iamAccount(), "bob", bobs.AccessKeyID, UserGrant(ctx, t, a, iamAccount(), "bob"))
			wantErr(t, "DeleteAccessKey again", err, resource.CodeNotFound,
				"The Access Key with name "+bobs.AccessKeyID+" cannot be found.")
			err = a.DeleteAccessKey(ctx, iamAccount(), "bob", "not-a-vws-key-id", UserGrant(ctx, t, a, iamAccount(), "bob"))
			wantErr(t, "DeleteAccessKey of an id vws-iam cannot hold", err, resource.CodeNotFound,
				"The Access Key with name not-a-vws-key-id cannot be found.")
			wantKeys(ctx, t, a, "alice", alices.AccessKeyID)
		}},
		{"GetAccessKeyLastUsed names the owner of a new key, never used", func(
			ctx context.Context, t *testing.T, a iam.Directory,
		) {
			k, err := a.CreateAccessKey(ctx, iamAccount(), "bob", UserGrant(ctx, t, a, iamAccount(), "bob"))
			wantOK(t, "CreateAccessKey", err)
			got, err := a.GetAccessKeyLastUsed(ctx, iamAccount(), k.AccessKeyID)
			wantOK(t, "GetAccessKeyLastUsed", err)
			if got.UserName != "bob" || got.UserARN != arnPrefix+"user/eng/bob" || !got.LastUsed.IsZero() ||
				got.Service != "" || got.Region != "" {
				t.Fatalf("GetAccessKeyLastUsed: %+v", got)
			}
			wantOK(
				t,
				"DeleteAccessKey",
				a.DeleteAccessKey(ctx, iamAccount(), "bob", k.AccessKeyID, UserGrant(ctx, t, a, iamAccount(), "bob")),
			)
			_, err = a.GetAccessKeyLastUsed(ctx, iamAccount(), k.AccessKeyID)
			wantErr(t, "GetAccessKeyLastUsed after the delete", err, resource.CodeNotFound,
				"The access key with id "+k.AccessKeyID+" cannot be found.")
		}},
		{"DeleteUser with an access key is DeleteConflict", func(ctx context.Context, t *testing.T, a iam.Directory) {
			k, err := a.CreateAccessKey(ctx, iamAccount(), "bob", UserGrant(ctx, t, a, iamAccount(), "bob"))
			wantOK(t, "CreateAccessKey", err)
			wantErr(
				t,
				"DeleteUser",
				a.DeleteUser(ctx, iamAccount(), "bob", UserGrant(ctx, t, a, iamAccount(), "bob")),
				resource.CodeConflict,
				iam.UserDeleteConflict,
			)
			wantOK(
				t,
				"DeleteAccessKey",
				a.DeleteAccessKey(ctx, iamAccount(), "bob", k.AccessKeyID, UserGrant(ctx, t, a, iamAccount(), "bob")),
			)
			wantOK(
				t,
				"DeleteUser once the key is gone",
				a.DeleteUser(ctx, iamAccount(), "bob", UserGrant(ctx, t, a, iamAccount(), "bob")),
			)
		}},
		{"another account sees none of the keys", func(ctx context.Context, t *testing.T, a iam.Directory) {
			k, err := a.CreateAccessKey(ctx, iamAccount(), "bob", UserGrant(ctx, t, a, iamAccount(), "bob"))
			wantOK(t, "CreateAccessKey", err)
			_, err = a.ListAccessKeys(ctx, iamOther(), "bob", UserGrant(ctx, t, a, iamOther(), "bob"))
			wantErr(t, "ListAccessKeys", err, resource.CodeNotFound, "")
			wantErr(t, "DeleteAccessKey", a.DeleteAccessKey(
				ctx, iamOther(), "bob", k.AccessKeyID, UserGrant(ctx, t, a, iamOther(), "bob"),
			),
				resource.CodeNotFound, "")
			_, err = a.GetAccessKeyLastUsed(ctx, iamOther(), k.AccessKeyID)
			wantErr(t, "GetAccessKeyLastUsed", err, resource.CodeNotFound, "")
			wantKeys(ctx, t, a, "bob", k.AccessKeyID)
		}},
		{"access key calls bound to a stale ARN are ConcurrentModification and change nothing", func(
			ctx context.Context, t *testing.T, a iam.Directory,
		) {
			// #325 r1: the surface passes the user ARN it authorized; a user
			// that has moved since must get no key, list none and lose none.
			stale := arnPrefix + "user/old/bob"
			k, err := a.CreateAccessKey(ctx, iamAccount(), "bob", Grant(ctx, t, arnPrefix+"user/eng/bob"))
			wantOK(t, "CreateAccessKey at the current ARN", err)
			changed := func(what string, err error) {
				t.Helper()
				wantErr(t, what, err, resource.CodeConflict, iam.UserChanged)
				if !iam.IsChanged(err) {
					t.Fatalf("%s: %v is not a ConcurrentModification", what, err)
				}
			}
			nk, err := a.CreateAccessKey(ctx, iamAccount(), "bob", Grant(ctx, t, stale))
			changed("CreateAccessKey", err)
			if nk.Secret != "" || nk.AccessKeyID != "" {
				t.Fatalf("a stale CreateAccessKey returned a key")
			}
			ks, err := a.ListAccessKeys(ctx, iamAccount(), "bob", Grant(ctx, t, stale))
			changed("ListAccessKeys", err)
			if len(ks) != 0 {
				t.Fatalf("a stale ListAccessKeys listed %q", keyIDs(ks))
			}
			changed("DeleteAccessKey", a.DeleteAccessKey(ctx, iamAccount(), "bob", k.AccessKeyID, Grant(ctx, t, stale)))
			wantKeys(ctx, t, a, "bob", k.AccessKeyID)
			ks, err = a.ListAccessKeys(ctx, iamAccount(), "bob", Grant(ctx, t, arnPrefix+"user/eng/bob"))
			wantOK(t, "ListAccessKeys at the current ARN", err)
			if len(ks) != 1 {
				t.Fatalf("keys at the current ARN: %q", keyIDs(ks))
			}
			wantOK(t, "DeleteAccessKey at the current ARN",
				a.DeleteAccessKey(ctx, iamAccount(), "bob", k.AccessKeyID, Grant(ctx, t, arnPrefix+"user/eng/bob")))
			wantKeys(ctx, t, a, "bob")
		}},
	}
}
