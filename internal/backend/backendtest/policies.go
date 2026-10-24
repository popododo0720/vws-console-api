package backendtest

import (
	"context"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// IAMPolicyHarness returns a fresh Admin and a way to seed a managed policy
// in it. vws-iam CreatePolicy is not served over gRPC yet, so the vws-iam
// stand-in seeds its policies directly; the fake calls CreatePolicy.
type IAMPolicyHarness func(t *testing.T) (iam.Directory, PolicySeeder)

// PolicySeeder creates the managed policy name at path in the contract
// account and returns its ARN.
type PolicySeeder func(t *testing.T, name, path string) string

// IAMEntityPolicies runs the #314 bundle 3 contract of the iam.Directory user and
// group policy calls, which the in-memory fake and the vws-iam client must
// answer alike. Each row starts from the IAMUsersAndGroups seed (alice
// /ops/, bob /eng/, devs /team/ with alice) and two managed policies:
// ReadOnly at / and Ops at /team/.
func IAMEntityPolicies(t *testing.T, newAdmin IAMPolicyHarness) {
	t.Helper()
	for _, row := range iamPolicyRows() {
		t.Run(row.name, func(t *testing.T) {
			ctx := context.Background()
			a, seed := newAdmin(t)
			seedIAM(ctx, t, a)
			p := seededPolicies{readOnly: seed(t, "ReadOnly", "/"), ops: seed(t, "Ops", "/team/"), seed: seed}
			row.run(ctx, t, a, p)
		})
	}
}

type seededPolicies struct {
	readOnly, ops string
	seed          PolicySeeder
}

type policyRow struct {
	name string
	run  func(ctx context.Context, t *testing.T, a iam.Directory, p seededPolicies)
}

// identityDoc is a valid identity policy on resource.
func identityDoc(res string) string {
	return `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"` +
		res + `"}]}`
}

// docOfSize is a valid identity policy of exactly n characters that are not
// white space, followed by pad spaces, which AWS does not count.
func docOfSize(t *testing.T, n, pad int) string {
	t.Helper()
	base := len(identityDoc("arn:vws:s3:::b/"))
	if n < base {
		t.Fatalf("docOfSize: %d is under the %d of an empty document", n, base)
	}
	return identityDoc("arn:vws:s3:::b/"+strings.Repeat("x", n-base)) + strings.Repeat(" ", pad)
}

func attachedARNs(ps []iam.ManagedPolicy) []string {
	out := []string{}
	for _, p := range ps {
		out = append(out, p.ARN)
	}
	return out
}

func wantAttached(ctx context.Context, t *testing.T, a iam.Directory, kind iam.Entity, name string, want ...string) {
	t.Helper()
	ps, err := a.ListAttachedPolicies(ctx, iamAccount(), kind, name, EntityGrant(ctx, t, a, iamAccount(), kind, name))
	wantOK(t, "ListAttachedPolicies "+name, err)
	if want == nil {
		want = []string{}
	}
	if got := attachedARNs(ps); !slices.Equal(got, want) {
		t.Fatalf("attached to %s: %q, want %q", name, got, want)
	}
	for _, p := range ps {
		if p.Name != p.ARN[strings.LastIndex(p.ARN, "/")+1:] {
			t.Fatalf("attached policy %+v: the name is not the end of the ARN", p)
		}
	}
}

func wantInline(ctx context.Context, t *testing.T, a iam.Directory, kind iam.Entity, name string, want ...string) {
	t.Helper()
	got, err := a.ListInlinePolicies(ctx, iamAccount(), kind, name, EntityGrant(ctx, t, a, iamAccount(), kind, name))
	wantOK(t, "ListInlinePolicies "+name, err)
	if want == nil {
		want = []string{}
	}
	if !slices.Equal(got, want) {
		t.Fatalf("inline policies of %s: %q, want %q", name, got, want)
	}
}

func wantField(t *testing.T, what string, err error, code resource.Code, field string) {
	t.Helper()
	wantErr(t, what, err, code, "")
	if got := resource.AsError(err).Field; got != field {
		t.Fatalf("%s: field %q, want %q (%v)", what, got, field, err)
	}
}

// policyHolder is the user or the group a row runs on.
type policyHolder struct {
	kind       iam.Entity
	name, word string // word: as in PoliciesPerUser
	arn        string
}

// holders are the user and the group every row runs on.
func holders() []policyHolder {
	return []policyHolder{
		{iam.EntityUser, "bob", "User", arnPrefix + "user/eng/bob"},
		{iam.EntityGroup, "devs", "Group", arnPrefix + "group/team/devs"},
	}
}

// iamPolicyRows are the #314 bundle 3 rows. Each runs on the user bob and on
// the group devs.
func iamPolicyRows() []policyRow {
	return []policyRow{
		{"Attach lists the policy by name with its path; a second attach is a no-op", func(
			ctx context.Context, t *testing.T, a iam.Directory, p seededPolicies,
		) {
			for _, h := range holders() {
				wantAttached(ctx, t, a, h.kind, h.name)
				wantOK(
					t,
					"Attach ReadOnly",
					a.AttachPolicy(
						ctx, iamAccount(), h.kind, h.name, p.readOnly, EntityGrant(ctx, t, a, iamAccount(), h.kind, h.name),
					),
				)
				wantOK(t, "Attach Ops", a.AttachPolicy(ctx, iamAccount(), h.kind, h.name, p.ops, Grant(ctx, t, h.arn)))
				wantOK(
					t,
					"Attach Ops again",
					a.AttachPolicy(ctx, iamAccount(), h.kind, h.name, p.ops, EntityGrant(ctx, t, a, iamAccount(), h.kind, h.name)),
				)
				wantAttached(ctx, t, a, h.kind, h.name, p.ops, p.readOnly)
				ps, err := a.ListAttachedPolicies(ctx, iamAccount(), h.kind, h.name, Grant(ctx, t, h.arn))
				wantOK(t, "ListAttachedPolicies at the ARN", err)
				if len(ps) != 2 || ps[0].Name != "Ops" || ps[0].ARN != arnPrefix+"policy/team/Ops" ||
					ps[1].Name != "ReadOnly" || ps[1].ARN != arnPrefix+"policy/ReadOnly" {
					t.Fatalf("attached %+v", ps)
				}
			}
			wantAttached(ctx, t, a, iam.EntityUser, "alice")
		}},
		{"an 11th managed policy is LimitExceeded; re-attaching one of the 10 is not", func(
			ctx context.Context, t *testing.T, a iam.Directory, p seededPolicies,
		) {
			var arns []string
			for i := range 11 {
				arns = append(arns, p.seed(t, "P"+string(rune('a'+i)), "/q/"))
			}
			for _, h := range holders() {
				for _, arn := range arns[:10] {
					wantOK(
						t,
						"Attach "+arn,
						a.AttachPolicy(ctx, iamAccount(), h.kind, h.name, arn, EntityGrant(ctx, t, a, iamAccount(), h.kind, h.name)),
					)
				}
				err := a.AttachPolicy(
					ctx, iamAccount(), h.kind, h.name, arns[10], EntityGrant(ctx, t, a, iamAccount(), h.kind, h.name),
				)
				wantErr(t, "Attach an 11th", err, resource.CodeResourceExhausted,
					"Cannot exceed quota for PoliciesPer"+h.word+": 10")
				wantOK(
					t,
					"Attach one of the 10 again",
					a.AttachPolicy(ctx, iamAccount(), h.kind, h.name, arns[3], EntityGrant(ctx, t, a, iamAccount(), h.kind, h.name)),
				)
				wantAttached(ctx, t, a, h.kind, h.name, arns[:10]...)
			}
			wantOK(
				t,
				"the quota is per entity",
				a.AttachPolicy(
					ctx,
					iamAccount(),
					iam.EntityUser,
					"alice",
					arns[10],
					EntityGrant(ctx, t, a, iamAccount(), iam.EntityUser, "alice"),
				),
			)
		}},
		{"Detach removes; a policy that is not attached is NoSuchEntity", func(
			ctx context.Context, t *testing.T, a iam.Directory, p seededPolicies,
		) {
			for _, h := range holders() {
				err := a.DetachPolicy(
					ctx, iamAccount(), h.kind, h.name, p.ops, EntityGrant(ctx, t, a, iamAccount(), h.kind, h.name),
				)
				wantErr(t, "Detach before attach", err, resource.CodeNotFound, "Policy "+p.ops+" was not found.")
				wantOK(
					t,
					"Attach",
					a.AttachPolicy(ctx, iamAccount(), h.kind, h.name, p.ops, EntityGrant(ctx, t, a, iamAccount(), h.kind, h.name)),
				)
				wantOK(
					t,
					"Attach",
					a.AttachPolicy(
						ctx, iamAccount(), h.kind, h.name, p.readOnly, EntityGrant(ctx, t, a, iamAccount(), h.kind, h.name),
					),
				)
				wantOK(t, "Detach", a.DetachPolicy(ctx, iamAccount(), h.kind, h.name, p.ops, Grant(ctx, t, h.arn)))
				wantAttached(ctx, t, a, h.kind, h.name, p.readOnly)
				err = a.DetachPolicy(ctx, iamAccount(), h.kind, h.name, p.ops, EntityGrant(ctx, t, a, iamAccount(), h.kind, h.name))
				wantErr(t, "Detach again", err, resource.CodeNotFound, "Policy "+p.ops+" was not found.")
			}
		}},
		{"a missing policy, another path or another account is NoSuchEntity", func(
			ctx context.Context, t *testing.T, a iam.Directory, p seededPolicies,
		) {
			for _, h := range holders() {
				for _, arn := range []string{
					arnPrefix + "policy/Ghost", arnPrefix + "policy/other/Ops", arnPrefix + "policy/Ops",
					"arn:vws:iam::210987654321:policy/team/Ops",
				} {
					err := a.AttachPolicy(ctx, iamAccount(), h.kind, h.name, arn, EntityGrant(ctx, t, a, iamAccount(), h.kind, h.name))
					wantErr(t, "Attach "+arn, err, resource.CodeNotFound, "Policy "+arn+" does not exist or is not attachable.")
					err = a.DetachPolicy(ctx, iamAccount(), h.kind, h.name, arn, EntityGrant(ctx, t, a, iamAccount(), h.kind, h.name))
					wantErr(t, "Detach "+arn, err, resource.CodeNotFound, "Policy "+arn+" does not exist or is not attachable.")
				}
				wantAttached(ctx, t, a, h.kind, h.name)
			}
		}},
		{"a missing user or group is NoSuchEntity on every call", func(
			ctx context.Context, t *testing.T, a iam.Directory, p seededPolicies,
		) {
			for _, h := range []struct {
				kind iam.Entity
				what string
			}{{iam.EntityUser, "user"}, {iam.EntityGroup, "group"}} {
				msg := "The " + h.what + " with name ghost cannot be found."
				wantErr(
					t,
					"Attach",
					a.AttachPolicy(ctx, iamAccount(), h.kind, "ghost", p.ops, EntityGrant(ctx, t, a, iamAccount(), h.kind, "ghost")),
					resource.CodeNotFound,
					msg,
				)
				wantErr(
					t,
					"Detach",
					a.DetachPolicy(ctx, iamAccount(), h.kind, "ghost", p.ops, EntityGrant(ctx, t, a, iamAccount(), h.kind, "ghost")),
					resource.CodeNotFound,
					msg,
				)
				_, err := a.ListAttachedPolicies(
					ctx, iamAccount(), h.kind, "ghost", EntityGrant(ctx, t, a, iamAccount(), h.kind, "ghost"),
				)
				wantErr(t, "ListAttached", err, resource.CodeNotFound, msg)
				err = a.PutInlinePolicy(
					ctx, iamAccount(), h.kind, "ghost", "p", identityDoc("*"), EntityGrant(ctx, t, a, iamAccount(), h.kind, "ghost"),
				)
				wantErr(t, "Put", err, resource.CodeNotFound, msg)
				_, err = a.GetInlinePolicy(
					ctx, iamAccount(), h.kind, "ghost", "p", EntityGrant(ctx, t, a, iamAccount(), h.kind, "ghost"),
				)
				wantErr(t, "Get", err, resource.CodeNotFound, msg)
				err = a.DeleteInlinePolicy(
					ctx, iamAccount(), h.kind, "ghost", "p", EntityGrant(ctx, t, a, iamAccount(), h.kind, "ghost"),
				)
				wantErr(t, "Delete", err, resource.CodeNotFound, msg)
				_, err = a.ListInlinePolicies(
					ctx, iamAccount(), h.kind, "ghost", EntityGrant(ctx, t, a, iamAccount(), h.kind, "ghost"),
				)
				wantErr(t, "List", err, resource.CodeNotFound, msg)
				// The entity is looked up before the ARN is compared.
				_, err = a.ListInlinePolicies(ctx, iamAccount(), h.kind, "ghost", Grant(ctx, t, arnPrefix+h.what+"/ghost"))
				wantErr(t, "List at an ARN", err, resource.CodeNotFound, msg)
			}
		}},
		{"inline policies round-trip byte for byte, list by name and are replaced by name", func(
			ctx context.Context, t *testing.T, a iam.Directory, _ seededPolicies,
		) {
			spaced := "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": {\"Effect\": \"Deny\", " +
				"\"Action\": [\"ec2:*\"], \"Resource\": \"*\"}\n}\n"
			for _, h := range holders() {
				wantInline(ctx, t, a, h.kind, h.name)
				wantOK(
					t,
					"Put s3",
					a.PutInlinePolicy(
						ctx, iamAccount(), h.kind, h.name, "s3", identityDoc("*"), EntityGrant(ctx, t, a, iamAccount(), h.kind, h.name),
					),
				)
				wantOK(t, "Put ec2", a.PutInlinePolicy(ctx, iamAccount(), h.kind, h.name, "ec2", spaced, Grant(ctx, t, h.arn)))
				wantInline(ctx, t, a, h.kind, h.name, "ec2", "s3")
				got, err := a.GetInlinePolicy(ctx, iamAccount(), h.kind, h.name, "ec2", Grant(ctx, t, h.arn))
				wantOK(t, "Get ec2", err)
				if got != spaced {
					t.Fatalf("Get ec2: %q, want %q", got, spaced)
				}
				other := identityDoc("arn:vws:s3:::other/*")
				wantOK(
					t,
					"Put s3 again",
					a.PutInlinePolicy(
						ctx, iamAccount(), h.kind, h.name, "s3", other, EntityGrant(ctx, t, a, iamAccount(), h.kind, h.name),
					),
				)
				got, err = a.GetInlinePolicy(
					ctx, iamAccount(), h.kind, h.name, "s3", EntityGrant(ctx, t, a, iamAccount(), h.kind, h.name),
				)
				wantOK(t, "Get s3", err)
				if got != other {
					t.Fatalf("Get s3 after the replace: %q", got)
				}
				wantInline(ctx, t, a, h.kind, h.name, "ec2", "s3")
			}
			wantInline(ctx, t, a, iam.EntityUser, "alice")
		}},
		{"Delete removes an inline policy; a missing one is NoSuchEntity", func(
			ctx context.Context, t *testing.T, a iam.Directory, _ seededPolicies,
		) {
			for _, h := range holders() {
				msg := "The " + h.kind.String() + " policy with name s3 cannot be found."
				_, err := a.GetInlinePolicy(
					ctx, iamAccount(), h.kind, h.name, "s3", EntityGrant(ctx, t, a, iamAccount(), h.kind, h.name),
				)
				wantErr(t, "Get before Put", err, resource.CodeNotFound, msg)
				wantErr(t, "Delete before Put", a.DeleteInlinePolicy(
					ctx, iamAccount(), h.kind, h.name, "s3", EntityGrant(ctx, t, a, iamAccount(), h.kind, h.name),
				),
					resource.CodeNotFound, msg)
				wantOK(
					t,
					"Put",
					a.PutInlinePolicy(
						ctx, iamAccount(), h.kind, h.name, "s3", identityDoc("*"), EntityGrant(ctx, t, a, iamAccount(), h.kind, h.name),
					),
				)
				wantOK(
					t,
					"Put",
					a.PutInlinePolicy(
						ctx, iamAccount(), h.kind, h.name, "ec2", identityDoc("*"), EntityGrant(ctx, t, a, iamAccount(), h.kind, h.name),
					),
				)
				wantOK(t, "Delete", a.DeleteInlinePolicy(ctx, iamAccount(), h.kind, h.name, "s3", Grant(ctx, t, h.arn)))
				wantInline(ctx, t, a, h.kind, h.name, "ec2")
				_, err = a.GetInlinePolicy(
					ctx, iamAccount(), h.kind, h.name, "s3", EntityGrant(ctx, t, a, iamAccount(), h.kind, h.name),
				)
				wantErr(t, "Get after Delete", err, resource.CodeNotFound, msg)
				wantErr(t, "Delete again", a.DeleteInlinePolicy(
					ctx, iamAccount(), h.kind, h.name, "s3", EntityGrant(ctx, t, a, iamAccount(), h.kind, h.name),
				),
					resource.CodeNotFound, msg)
			}
		}},
		{"a malformed document is MalformedPolicyDocument and nothing is stored", func(
			ctx context.Context, t *testing.T, a iam.Directory, _ seededPolicies,
		) {
			for _, h := range holders() {
				for _, doc := range []string{
					`not json`,
					`{"Version":"2012-10-17"}`,
					`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject"}]}`,
					`{"Version":"2012-10-17","Statement":[{"Effect":"Maybe","Action":"s3:*","Resource":"*"}]}`,
					`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:*","Resource":"*"}]}`,
				} {
					err := a.PutInlinePolicy(
						ctx, iamAccount(), h.kind, h.name, "bad", doc, EntityGrant(ctx, t, a, iamAccount(), h.kind, h.name),
					)
					wantField(t, "Put "+doc, err, resource.CodeInvalidArgument, "PolicyDocument")
				}
				wantInline(ctx, t, a, h.kind, h.name)
			}
		}},
		{"an inline policy name outside the AWS pattern is a ValidationError", func(
			ctx context.Context, t *testing.T, a iam.Directory, _ seededPolicies,
		) {
			for _, h := range holders() {
				for _, name := range []string{"", "bad name", "a/b", strings.Repeat("p", 129)} {
					err := a.PutInlinePolicy(
						ctx, iamAccount(), h.kind, h.name, name, identityDoc("*"), EntityGrant(ctx, t, a, iamAccount(), h.kind, h.name),
					)
					wantField(t, "Put "+name, err, resource.CodeInvalidArgument, "policyName")
				}
				ok := "p+=,.@_-9"
				wantOK(
					t,
					"Put "+ok,
					a.PutInlinePolicy(
						ctx, iamAccount(), h.kind, h.name, ok, identityDoc("*"), EntityGrant(ctx, t, a, iamAccount(), h.kind, h.name),
					),
				)
				wantInline(ctx, t, a, h.kind, h.name, ok)
			}
		}},
		{"the inline policies of an entity share the AWS size limit, white space not counted", func(
			ctx context.Context, t *testing.T, a iam.Directory, _ seededPolicies,
		) {
			for _, h := range []struct {
				kind  iam.Entity
				name  string
				what  string
				limit int
			}{{iam.EntityUser, "bob", "user", 2048}, {iam.EntityGroup, "devs", "group", 5120}} {
				msg := "Maximum policy size of " + strconv.Itoa(h.limit) + " bytes exceeded for " + h.what + " " + h.name + "."
				err := a.PutInlinePolicy(
					ctx,
					iamAccount(),
					h.kind,
					h.name,
					"big",
					docOfSize(t, h.limit+1, 0),
					EntityGrant(ctx, t, a, iamAccount(), h.kind, h.name),
				)
				wantErr(t, "Put one over the limit", err, resource.CodeResourceExhausted, msg)
				wantOK(t, "Put at the limit with white space",
					a.PutInlinePolicy(
						ctx,
						iamAccount(),
						h.kind,
						h.name,
						"big",
						docOfSize(t, h.limit-200, 400),
						EntityGrant(ctx, t, a, iamAccount(), h.kind, h.name),
					))
				err = a.PutInlinePolicy(
					ctx,
					iamAccount(),
					h.kind,
					h.name,
					"more",
					docOfSize(t, 201, 0),
					EntityGrant(ctx, t, a, iamAccount(), h.kind, h.name),
				)
				wantErr(t, "Put past the sum", err, resource.CodeResourceExhausted, msg)
				wantOK(t, "Put up to the sum",
					a.PutInlinePolicy(
						ctx,
						iamAccount(),
						h.kind,
						h.name,
						"more",
						docOfSize(t, 200, 0),
						EntityGrant(ctx, t, a, iamAccount(), h.kind, h.name),
					))
				wantOK(t, "a replaced policy counts once",
					a.PutInlinePolicy(
						ctx,
						iamAccount(),
						h.kind,
						h.name,
						"big",
						docOfSize(t, h.limit-200, 0),
						EntityGrant(ctx, t, a, iamAccount(), h.kind, h.name),
					))
				wantInline(ctx, t, a, h.kind, h.name, "big", "more")
			}
		}},
		{"DeleteUser and DeleteGroup with a policy are DeleteConflict", func(
			ctx context.Context, t *testing.T, a iam.Directory, p seededPolicies,
		) {
			wantOK(
				t,
				"Attach",
				a.AttachPolicy(
					ctx, iamAccount(), iam.EntityUser, "bob", p.ops, EntityGrant(ctx, t, a, iamAccount(), iam.EntityUser, "bob"),
				),
			)
			wantErr(
				t,
				"DeleteUser",
				a.DeleteUser(ctx, iamAccount(), "bob", UserGrant(ctx, t, a, iamAccount(), "bob")),
				resource.CodeConflict,
				iam.UserDeleteConflict,
			)
			wantOK(
				t,
				"Detach",
				a.DetachPolicy(
					ctx, iamAccount(), iam.EntityUser, "bob", p.ops, EntityGrant(ctx, t, a, iamAccount(), iam.EntityUser, "bob"),
				),
			)
			wantOK(
				t,
				"Put",
				a.PutInlinePolicy(
					ctx,
					iamAccount(),
					iam.EntityUser,
					"bob",
					"s3",
					identityDoc("*"),
					EntityGrant(ctx, t, a, iamAccount(), iam.EntityUser, "bob"),
				),
			)
			wantErr(
				t,
				"DeleteUser",
				a.DeleteUser(ctx, iamAccount(), "bob", UserGrant(ctx, t, a, iamAccount(), "bob")),
				resource.CodeConflict,
				iam.UserDeleteConflict,
			)
			wantOK(
				t,
				"Delete inline",
				a.DeleteInlinePolicy(
					ctx, iamAccount(), iam.EntityUser, "bob", "s3", EntityGrant(ctx, t, a, iamAccount(), iam.EntityUser, "bob"),
				),
			)
			wantOK(
				t,
				"DeleteUser once the policies are gone",
				a.DeleteUser(ctx, iamAccount(), "bob", UserGrant(ctx, t, a, iamAccount(), "bob")),
			)

			wantOK(
				t,
				"RemoveUserFromGroup",
				a.RemoveUserFromGroup(ctx, iamAccount(), "devs", "alice", GroupGrant(ctx, t, a, iamAccount(), "devs")),
			)
			wantOK(
				t,
				"Put",
				a.PutInlinePolicy(
					ctx,
					iamAccount(),
					iam.EntityGroup,
					"devs",
					"s3",
					identityDoc("*"),
					EntityGrant(ctx, t, a, iamAccount(), iam.EntityGroup, "devs"),
				),
			)
			wantErr(t, "DeleteGroup", a.DeleteGroup(ctx, iamAccount(), "devs", GroupGrant(ctx, t, a, iamAccount(), "devs")),
				resource.CodeConflict, iam.GroupDeleteConflict)
			wantOK(
				t,
				"Delete inline",
				a.DeleteInlinePolicy(
					ctx, iamAccount(), iam.EntityGroup, "devs", "s3", EntityGrant(ctx, t, a, iamAccount(), iam.EntityGroup, "devs"),
				),
			)
			wantOK(
				t,
				"Attach",
				a.AttachPolicy(
					ctx,
					iamAccount(),
					iam.EntityGroup,
					"devs",
					p.readOnly,
					EntityGrant(ctx, t, a, iamAccount(), iam.EntityGroup, "devs"),
				),
			)
			wantErr(t, "DeleteGroup", a.DeleteGroup(ctx, iamAccount(), "devs", GroupGrant(ctx, t, a, iamAccount(), "devs")),
				resource.CodeConflict, iam.GroupDeleteConflict)
			wantOK(
				t,
				"Detach",
				a.DetachPolicy(
					ctx,
					iamAccount(),
					iam.EntityGroup,
					"devs",
					p.readOnly,
					EntityGrant(ctx, t, a, iamAccount(), iam.EntityGroup, "devs"),
				),
			)
			wantOK(
				t,
				"DeleteGroup once the policies are gone",
				a.DeleteGroup(ctx, iamAccount(), "devs", GroupGrant(ctx, t, a, iamAccount(), "devs")),
			)
		}},
		{"every call at a stale ARN is ConcurrentModification and writes nothing", func(
			ctx context.Context, t *testing.T, a iam.Directory, p seededPolicies,
		) {
			for _, h := range holders() {
				wantOK(
					t,
					"Attach",
					a.AttachPolicy(
						ctx, iamAccount(), h.kind, h.name, p.readOnly, EntityGrant(ctx, t, a, iamAccount(), h.kind, h.name),
					),
				)
				wantOK(
					t,
					"Put",
					a.PutInlinePolicy(
						ctx, iamAccount(), h.kind, h.name, "s3", identityDoc("*"), EntityGrant(ctx, t, a, iamAccount(), h.kind, h.name),
					),
				)
				old := strings.Replace(h.arn, "/eng/", "/old/", 1)
				old = strings.Replace(old, "/team/", "/old/", 1)
				msg := iam.UserChanged
				if h.kind == iam.EntityGroup {
					msg = iam.GroupChanged
				}
				changed := func(what string, err error) {
					t.Helper()
					wantErr(t, what, err, resource.CodeConflict, msg)
					if !iam.IsChanged(err) {
						t.Fatalf("%s: %v is not a ConcurrentModification", what, err)
					}
				}
				changed("Attach", a.AttachPolicy(ctx, iamAccount(), h.kind, h.name, p.ops, Grant(ctx, t, old)))
				changed(
					"Attach of an attached policy", a.AttachPolicy(ctx, iamAccount(), h.kind, h.name, p.readOnly, Grant(ctx, t, old)),
				)
				changed("Detach", a.DetachPolicy(ctx, iamAccount(), h.kind, h.name, p.readOnly, Grant(ctx, t, old)))
				_, err := a.ListAttachedPolicies(ctx, iamAccount(), h.kind, h.name, Grant(ctx, t, old))
				changed("ListAttached", err)
				changed("Put", a.PutInlinePolicy(ctx, iamAccount(), h.kind, h.name, "ec2", identityDoc("*"), Grant(ctx, t, old)))
				_, err = a.GetInlinePolicy(ctx, iamAccount(), h.kind, h.name, "s3", Grant(ctx, t, old))
				changed("Get", err)
				_, err = a.GetInlinePolicy(ctx, iamAccount(), h.kind, h.name, "missing", Grant(ctx, t, old))
				changed("Get of a missing policy", err)
				changed("Delete", a.DeleteInlinePolicy(ctx, iamAccount(), h.kind, h.name, "s3", Grant(ctx, t, old)))
				_, err = a.ListInlinePolicies(ctx, iamAccount(), h.kind, h.name, Grant(ctx, t, old))
				changed("List", err)
				wantAttached(ctx, t, a, h.kind, h.name, p.readOnly)
				wantInline(ctx, t, a, h.kind, h.name, "s3")
			}
		}},
		{"another account sees none of the policies", func(
			ctx context.Context, t *testing.T, a iam.Directory, p seededPolicies,
		) {
			wantOK(
				t,
				"Attach",
				a.AttachPolicy(
					ctx, iamAccount(), iam.EntityUser, "bob", p.ops, EntityGrant(ctx, t, a, iamAccount(), iam.EntityUser, "bob"),
				),
			)
			wantOK(
				t,
				"Put",
				a.PutInlinePolicy(
					ctx,
					iamAccount(),
					iam.EntityUser,
					"bob",
					"s3",
					identityDoc("*"),
					EntityGrant(ctx, t, a, iamAccount(), iam.EntityUser, "bob"),
				),
			)
			_, err := a.ListAttachedPolicies(
				ctx, iamOther(), iam.EntityUser, "bob", EntityGrant(ctx, t, a, iamOther(), iam.EntityUser, "bob"),
			)
			wantErr(t, "ListAttached", err, resource.CodeNotFound, "")
			_, err = a.GetInlinePolicy(
				ctx, iamOther(), iam.EntityUser, "bob", "s3", EntityGrant(ctx, t, a, iamOther(), iam.EntityUser, "bob"),
			)
			wantErr(t, "Get", err, resource.CodeNotFound, "")
			wantErr(
				t,
				"Detach",
				a.DetachPolicy(
					ctx, iamOther(), iam.EntityUser, "bob", p.ops, EntityGrant(ctx, t, a, iamOther(), iam.EntityUser, "bob"),
				),
				resource.CodeNotFound,
				"",
			)
			wantErr(t, "Delete", a.DeleteInlinePolicy(
				ctx, iamOther(), iam.EntityUser, "bob", "s3", EntityGrant(ctx, t, a, iamOther(), iam.EntityUser, "bob"),
			),
				resource.CodeNotFound, "")
			wantAttached(ctx, t, a, iam.EntityUser, "bob", p.ops)
			wantInline(ctx, t, a, iam.EntityUser, "bob", "s3")
		}},
	}
}
