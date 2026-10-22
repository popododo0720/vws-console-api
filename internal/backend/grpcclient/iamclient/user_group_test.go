package iamclient

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// GetUser and GetGroup read vws-iam's UserService and GroupService by
// resource name and keep NoSuchEntity a NotFound with the AWS message.
func TestGetUserAndGetGroupOverGRPC(t *testing.T) {
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	t.Run("requests", func(t *testing.T) {
		_, s := queryHarness(t)
		a := STSAdmin{Client: s.client}
		u, err := a.GetUser(t.Context(), account, "alice")
		if err != nil || u.Name != "alice" || u.Path != "/ops/" || u.ARN != aliceARN || u.ID != "AIDAALICE00000000001" {
			t.Fatalf("GetUser: %+v %v", u, err)
		}
		g, members, err := a.GetGroup(t.Context(), account, "devs")
		if err != nil || g.Name != "devs" || g.Path != "/team/" || g.ARN != devsARN ||
			len(members) != 1 || members[0].ARN != aliceARN {
			t.Fatalf("GetGroup: %+v %+v %v", g, members, err)
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if got := s.getGroup[0].GetName(); got != "projects/123456789012/groups/devs" {
			t.Errorf("GetGroup sent %q", got)
		}
		if got := s.getUser[0].GetName(); got != "projects/123456789012/users/alice" {
			t.Errorf("GetUser sent %q", got)
		}
	})
	t.Run("a name that is not one segment is not sent", func(t *testing.T) {
		_, s := queryHarness(t)
		a := STSAdmin{Client: s.client}
		if _, err := a.GetUser(t.Context(), account, "alice/../bob"); resource.CodeOf(err) != resource.CodeNotFound {
			t.Errorf("GetUser: %v", err)
		}
		if _, _, err := a.GetGroup(t.Context(), account, ""); resource.CodeOf(err) != resource.CodeNotFound {
			t.Errorf("GetGroup: %v", err)
		}
		if n := lookups(s); n != 0 {
			t.Errorf("%d calls reached vws-iam", n)
		}
	})
	t.Run("a member outside the account is an internal error", func(t *testing.T) {
		_, s := queryHarness(t)
		s.getGroupRes["projects/123456789012/groups/devs"].Spec.Members = []string{"projects/999999999999/users/eve"}
		_, _, err := STSAdmin{Client: s.client}.GetGroup(t.Context(), account, "devs")
		if resource.CodeOf(err) != resource.CodeInternal {
			t.Errorf("got %v", err)
		}
	})
	t.Run("a group outside the account is an internal error", func(t *testing.T) {
		_, s := queryHarness(t)
		s.getGroupRes["projects/123456789012/groups/devs"].Status.Arn = "arn:vws:iam::999999999999:group/devs"
		_, _, err := STSAdmin{Client: s.client}.GetGroup(t.Context(), account, "devs")
		if resource.CodeOf(err) != resource.CodeInternal {
			t.Errorf("got %v", err)
		}
	})
	t.Run("a member lookup outage fails the group", func(t *testing.T) {
		_, s := queryHarness(t)
		s.getUserErr = status.Error(codes.Unavailable, vwsIAMMsg)
		if _, _, err := (STSAdmin{Client: s.client}).GetGroup(t.Context(), account, "devs"); err == nil {
			t.Error("GetGroup succeeded without its members")
		}
	})
	t.Run("missing", func(t *testing.T) {
		_, s := queryHarness(t)
		a := STSAdmin{Client: s.client}
		_, err := a.GetUser(t.Context(), account, "ghost")
		if !noSuchEntity(err, "The user with name ghost cannot be found.") {
			t.Errorf("GetUser: %v", err)
		}
		_, _, err = a.GetGroup(t.Context(), account, "ghost")
		if !noSuchEntity(err, "The group with name ghost cannot be found.") {
			t.Errorf("GetGroup: %v", err)
		}
	})
}

func noSuchEntity(err error, msg string) bool {
	return resource.CodeOf(err) == resource.CodeNotFound && resource.AsError(err).Message == msg
}
