package iamclient

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/timestamppb"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// GetUser is what the IAM Query surface reads to authorize a user-scoped
// action on the user's real ARN, path included.
func TestGetUserOverGRPC(t *testing.T) {
	c, s := harness(t)
	name := "projects/123456789012/users/alice"
	s.getUserRes = map[string]*iamv1.User{name: {
		Name: name,
		Spec: &iamv1.UserSpec{Path: "/restricted/"},
		Status: &iamv1.UserStatus{
			Arn: "arn:vws:iam::123456789012:user/restricted/alice", UniqueId: "AIDAALICE",
		},
		CreateTime: timestamppb.New(authTime),
	}}
	got, err := STSAdmin{Client: c}.GetUser(t.Context(), account(t), "alice")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "alice" || got.Path != "/restricted/" ||
		got.ARN != "arn:vws:iam::123456789012:user/restricted/alice" ||
		got.ID != "AIDAALICE" || !got.Created.Equal(authTime) {
		t.Fatalf("user %+v", got)
	}
	if len(s.getUser) != 1 || s.getUser[0].GetName() != name {
		t.Errorf("read %v, want %q", s.getUser, name)
	}
}

func TestGetUserOverGRPCMapsNotFound(t *testing.T) {
	c, s := harness(t)
	s.getUserErr = awsErr(codes.NotFound, "NOT_FOUND", "NoSuchEntity")
	_, err := (STSAdmin{Client: c}).GetUser(t.Context(), account(t), "ghost")
	if resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("missing user: %v, want NoSuchEntity", err)
	}
}

// A user that vws-iam names outside the caller's account is an internal
// error, never a user the surface can authorize on.
func TestGetUserOverGRPCRejectsForeignUser(t *testing.T) {
	c, s := harness(t)
	name := "projects/123456789012/users/alice"
	s.getUserRes = map[string]*iamv1.User{name: {
		Name:   name,
		Status: &iamv1.UserStatus{Arn: "arn:vws:iam::210987654321:user/alice"},
	}}
	_, err := (STSAdmin{Client: c}).GetUser(t.Context(), account(t), "alice")
	if resource.CodeOf(err) != resource.CodeInternal {
		t.Fatalf("foreign user: %v, want internal", err)
	}
}
