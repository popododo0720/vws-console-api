package iamclient

import (
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

const lastUsedKeyID = "AKIAABCDEFGHIJKLMNOP"

func TestGetAccessKeyLastUsedOverGRPC(t *testing.T) {
	c, s := harness(t)
	acct := account(t)
	s.listUsersRes = &iamv1.ListUsersResponse{Users: []*iamv1.User{
		{Name: "projects/123456789012/users/alice", Status: &iamv1.UserStatus{Arn: "arn:vws:iam::123456789012:user/alice"}},
		{Name: "projects/123456789012/users/bob", Status: &iamv1.UserStatus{Arn: "arn:vws:iam::123456789012:user/bob"}},
	}}
	s.getAccessKeyOwner = "bob"
	s.getAccessKeyRes = &iamv1.AccessKey{
		Name: "projects/123456789012/users/bob/accessKeys/" + lastUsedKeyID,
		Status: &iamv1.AccessKeyStatus{
			LastUsedTime: timestamppb.New(authTime), LastUsedService: "s3", LastUsedRegion: "vws-1",
		},
	}
	got, err := STSAdmin{Client: c}.GetAccessKeyLastUsed(t.Context(), acct, lastUsedKeyID)
	if err != nil {
		t.Fatal(err)
	}
	if got.UserName != "bob" || got.UserARN != "arn:vws:iam::123456789012:user/bob" ||
		!got.LastUsed.Equal(authTime) || got.Service != "s3" || got.Region != "vws-1" {
		t.Fatalf("last used %+v", got)
	}
	if len(s.getAccessKey) != 2 {
		t.Fatalf("read %d keys, want alice then bob", len(s.getAccessKey))
	}
	for i, user := range []string{"alice", "bob"} {
		want := "projects/123456789012/users/" + user + "/accessKeys/" + lastUsedKeyID
		if s.getAccessKey[i].GetName() != want {
			t.Errorf("read %q, want %q", s.getAccessKey[i].GetName(), want)
		}
	}
	if len(s.listUsers) != 1 || s.listUsers[0].GetParent() != "projects/123456789012" {
		t.Errorf("list users %v", s.listUsers)
	}
}

func TestGetAccessKeyLastUsedNeverUsed(t *testing.T) {
	c, s := harness(t)
	s.listUsersRes = &iamv1.ListUsersResponse{Users: []*iamv1.User{
		{Name: "projects/123456789012/users/bob", Status: &iamv1.UserStatus{Arn: "arn:vws:iam::123456789012:user/bob"}},
	}}
	s.getAccessKeyRes = &iamv1.AccessKey{Name: "projects/123456789012/users/bob/accessKeys/" + lastUsedKeyID}
	got, err := STSAdmin{Client: c}.GetAccessKeyLastUsed(t.Context(), account(t), lastUsedKeyID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.LastUsed.IsZero() || got.Service != "" || got.Region != "" {
		t.Fatalf("unused key %+v", got)
	}
}

func TestGetAccessKeyLastUsedMissingKey(t *testing.T) {
	c, s := harness(t)
	s.listUsersRes = &iamv1.ListUsersResponse{Users: []*iamv1.User{
		{Name: "projects/123456789012/users/bob"},
	}}
	s.getAccessKeyErr = status.Error(codes.NotFound, "no such key")
	_, err := STSAdmin{Client: c}.GetAccessKeyLastUsed(t.Context(), account(t), lastUsedKeyID)
	if resource.CodeOf(err) != resource.CodeNotFound || !strings.Contains(err.Error(), "cannot be found") {
		t.Fatalf("missing key: %v", err)
	}
}

func TestGetAccessKeyLastUsedPaginates(t *testing.T) {
	c, s := harness(t)
	s.listUsersPages = map[string]*iamv1.ListUsersResponse{
		"": {Users: []*iamv1.User{{Name: "projects/123456789012/users/alice"}}, NextPageToken: "page2"},
		"page2": {Users: []*iamv1.User{{
			Name: "projects/123456789012/users/bob", Status: &iamv1.UserStatus{Arn: "arn:vws:iam::123456789012:user/bob"},
		}}},
	}
	s.getAccessKeyOwner = "bob"
	s.getAccessKeyRes = &iamv1.AccessKey{Name: "projects/123456789012/users/bob/accessKeys/" + lastUsedKeyID}
	got, err := STSAdmin{Client: c}.GetAccessKeyLastUsed(t.Context(), account(t), lastUsedKeyID)
	if err != nil || got.UserName != "bob" {
		t.Fatalf("paged key %+v %v", got, err)
	}
	if len(s.listUsers) != 2 || s.listUsers[0].GetPageToken() != "" || s.listUsers[1].GetPageToken() != "page2" {
		t.Errorf("list users %v", s.listUsers)
	}
	if len(s.getAccessKey) != 2 {
		t.Errorf("read %d keys, want alice then bob", len(s.getAccessKey))
	}
}

func TestGetAccessKeyLastUsedWrongKeyName(t *testing.T) {
	c, s := harness(t)
	s.listUsersRes = &iamv1.ListUsersResponse{Users: []*iamv1.User{{
		Name: "projects/123456789012/users/bob", Status: &iamv1.UserStatus{Arn: "arn:vws:iam::123456789012:user/bob"},
	}}}
	s.getAccessKeyRes = &iamv1.AccessKey{Name: "projects/123456789012/users/alice/accessKeys/" + lastUsedKeyID}
	_, err := STSAdmin{Client: c}.GetAccessKeyLastUsed(t.Context(), account(t), lastUsedKeyID)
	if resource.CodeOf(err) != resource.CodeInternal {
		t.Fatalf("wrong key name: %v", err)
	}
}

func TestGetAccessKeyLastUsedNoOwnerARN(t *testing.T) {
	c, s := harness(t)
	s.listUsersRes = &iamv1.ListUsersResponse{Users: []*iamv1.User{{
		Name: "projects/123456789012/users/bob",
	}}}
	s.getAccessKeyRes = &iamv1.AccessKey{Name: "projects/123456789012/users/bob/accessKeys/" + lastUsedKeyID}
	_, err := STSAdmin{Client: c}.GetAccessKeyLastUsed(t.Context(), account(t), lastUsedKeyID)
	if resource.CodeOf(err) != resource.CodeInternal {
		t.Fatalf("owner without ARN: %v", err)
	}
}
