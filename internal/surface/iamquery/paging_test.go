package iamquery

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// #314: ListUsers, ListGroups, ListGroupsForUser and GetGroup page with
// Marker and MaxItems as AWS does: MaxItems 1 to 1000, default 100,
// IsTruncated and a Marker for the next page.
func TestIAMListsPageWithMarkerAndMaxItems(t *testing.T) {
	h, f, _, cred := harness(t)
	ctx := context.Background()
	for _, n := range []string{"ann", "ben", "cat"} {
		if _, err := f.CreateUser(ctx, cred.Account, n, "/p/"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.CreateUser(ctx, cred.Account, "dan", "/q/"); err != nil {
		t.Fatal(err)
	}
	for _, g := range []string{"g1", "g2", "g3"} {
		if _, err := f.CreateGroup(ctx, cred.Account, g, "/"); err != nil {
			t.Fatal(err)
		}
		if err := f.AddUserToGroup(ctx, cred.Account, g, "ann"); err != nil {
			t.Fatal(err)
		}
	}
	for _, u := range []string{"ben", "cat"} {
		if err := f.AddUserToGroup(ctx, cred.Account, "g1", u); err != nil {
			t.Fatal(err)
		}
	}
	type page struct {
		form  url.Values
		want  []string
		wantN int
		trunc bool
	}
	for _, tc := range []struct {
		name string
		page page
		not  []string
	}{
		{
			"ListUsers first page",
			page{
				url.Values{"Action": {"ListUsers"}, "MaxItems": {"2"}},
				[]string{
					"<UserName>ann</UserName>", "<UserName>ben</UserName>",
					"<IsTruncated>true</IsTruncated>", "<Marker>ben</Marker>",
				},
				2, true,
			},
			[]string{"<UserName>cat</UserName>"},
		},
		{
			"ListUsers next page",
			page{
				url.Values{"Action": {"ListUsers"}, "MaxItems": {"2"}, "Marker": {"ben"}},
				[]string{"<UserName>cat</UserName>", "<UserName>dan</UserName>", "<IsTruncated>false</IsTruncated>"},
				2, false,
			},
			[]string{"<Marker>", "<UserName>ben</UserName>"},
		},
		{
			"ListUsers path prefix pages too",
			page{
				url.Values{"Action": {"ListUsers"}, "PathPrefix": {"/p/"}, "MaxItems": {"2"}, "Marker": {"ben"}},
				[]string{"<UserName>cat</UserName>", "<IsTruncated>false</IsTruncated>"},
				1, false,
			},
			[]string{"<UserName>dan</UserName>"},
		},
		{"ListUsers default is everything up to 100", page{
			url.Values{"Action": {"ListUsers"}},
			[]string{"<UserName>dan</UserName>", "<IsTruncated>false</IsTruncated>"},
			4, false,
		}, nil},
		{"ListGroups pages", page{
			url.Values{"Action": {"ListGroups"}, "MaxItems": {"1"}, "Marker": {"g1"}},
			[]string{"<GroupName>g2</GroupName>", "<IsTruncated>true</IsTruncated>", "<Marker>g2</Marker>"},
			1, true,
		}, nil},
		{"ListGroupsForUser pages", page{
			url.Values{"Action": {"ListGroupsForUser"}, "UserName": {"ann"}, "MaxItems": {"2"}},
			[]string{"<GroupName>g1</GroupName>", "<GroupName>g2</GroupName>", "<Marker>g2</Marker>"},
			2, true,
		}, nil},
		{
			"GetGroup pages members",
			page{
				url.Values{"Action": {"GetGroup"}, "GroupName": {"g1"}, "MaxItems": {"1"}, "Marker": {"ann"}},
				[]string{
					"<GroupName>g1</GroupName>", "<UserName>ben</UserName>",
					"<IsTruncated>true</IsTruncated>", "<Marker>ben</Marker>",
				},
				1, true,
			},
			[]string{"<UserName>cat</UserName>"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := call(t, h, cred, "iam", tc.page.form)
			has(t, res, http.StatusOK, tc.page.want...)
			for _, n := range tc.not {
				if strings.Contains(res.Body.String(), n) {
					t.Errorf("unexpected %q in %s", n, res.Body.String())
				}
			}
			tag := "<member>"
			body := res.Body.String()
			if got := strings.Count(body, tag) - strings.Count(body, "<Group><member>"); got != tc.page.wantN {
				t.Errorf("%d members, want %d: %s", got, tc.page.wantN, res.Body.String())
			}
		})
	}
}

// #314: the List actions validate Marker, MaxItems and PathPrefix and the
// required names before any lookup, with the AWS error codes.
func TestIAMListParametersAreValidated(t *testing.T) {
	h, f, _, cred := harness(t)
	if _, err := f.CreateGroup(context.Background(), cred.Account, "g1", "/"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		form url.Values
		code string
	}{
		{"MaxItems zero", url.Values{"Action": {"ListUsers"}, "MaxItems": {"0"}}, "ValidationError"},
		{"MaxItems over 1000", url.Values{"Action": {"ListGroups"}, "MaxItems": {"1001"}}, "ValidationError"},
		{
			"MaxItems not a number",
			url.Values{"Action": {"GetGroup"}, "GroupName": {"g1"}, "MaxItems": {"x"}},
			"ValidationError",
		},
		{"empty Marker", url.Values{"Action": {"ListUsers"}, "Marker": {""}}, "InvalidInput"},
		{"Marker out of range", url.Values{"Action": {"ListGroups"}, "Marker": {"a\x01"}}, "InvalidInput"},
		{"PathPrefix without a slash", url.Values{"Action": {"ListUsers"}, "PathPrefix": {"eng"}}, "ValidationError"},
		{"empty PathPrefix", url.Values{"Action": {"ListGroups"}, "PathPrefix": {""}}, "ValidationError"},
		{
			"PathPrefix too long",
			url.Values{"Action": {"ListUsers"}, "PathPrefix": {"/" + strings.Repeat("a", 512)}},
			"ValidationError",
		},
		{"ListGroupsForUser without UserName", url.Values{"Action": {"ListGroupsForUser"}}, "ValidationError"},
		{"DeleteGroup without GroupName", url.Values{"Action": {"DeleteGroup"}}, "ValidationError"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			has(t, call(t, h, cred, "iam", tc.form), http.StatusBadRequest, "<Code>"+tc.code+"</Code>")
		})
	}
}
