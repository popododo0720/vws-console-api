// Package iamtest provides a shared AuthService fixture for console session tests.
package iamtest

import (
	"context"
	"fmt"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"
)

// AuthService owns session tokens independently of any console client.
type AuthService struct {
	iamv1.UnimplementedAuthServiceServer
	mu     sync.Mutex
	tokens map[string]*iamv1.Principal
	logins []string
}

// Serve starts a loopback TCP AuthService and stops it when the test ends.
func Serve(t *testing.T) (string, *AuthService) {
	t.Helper()
	store := &AuthService{tokens: make(map[string]*iamv1.Principal)}
	lis, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	g := grpc.NewServer()
	iamv1.RegisterAuthServiceServer(g, store)
	done := make(chan error, 1)
	go func() { done <- g.Serve(lis) }()
	t.Cleanup(func() {
		g.Stop()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("AuthService: %v", err)
			}
		case <-time.After(30 * time.Second):
			t.Error("AuthService did not stop")
		}
	})
	return lis.Addr().String(), store
}

// Login accepts the fixture's root and bob identities in account 123456789012.
func (s *AuthService) Login(_ context.Context, r *iamv1.LoginRequest) (*iamv1.LoginResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.GetProject() != "123456789012" || r.GetPassword() != "correct horse 1" ||
		(r.GetUserName() != "bob" && r.GetUserName() != "root") {
		return nil, status.Error(codes.Unauthenticated, "invalid credentials")
	}
	p := &iamv1.Principal{
		Type: iamv1.PrincipalType_PRINCIPAL_TYPE_USER, Project: r.GetProject(),
		Arn: "arn:vws:iam::123456789012:user/bob", UniqueId: "AIDABOB",
	}
	if r.GetUserName() == "root" {
		p.Type, p.Arn, p.UniqueId = iamv1.PrincipalType_PRINCIPAL_TYPE_ROOT,
			"arn:vws:iam::123456789012:root", r.GetProject()
	}
	s.logins = append(s.logins, r.GetUserName())
	token := fmt.Sprintf("session-%d", len(s.logins))
	s.tokens[token] = p
	return &iamv1.LoginResponse{
		SessionToken: token, Principal: p, ExpireTime: timestamppb.New(time.Now().Add(time.Hour)),
	}, nil
}

// ValidateSession rejects unknown and revoked tokens.
func (s *AuthService) ValidateSession(
	_ context.Context, r *iamv1.ValidateSessionRequest,
) (*iamv1.ValidateSessionResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.tokens[r.GetSessionToken()]
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "invalid session")
	}
	return &iamv1.ValidateSessionResponse{
		Principal: p, ExpireTime: timestamppb.New(time.Now().Add(time.Hour)),
	}, nil
}

// Logout revokes a token; an unknown token is harmless.
func (s *AuthService) Logout(_ context.Context, r *iamv1.LogoutRequest) (*iamv1.LogoutResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, r.GetSessionToken())
	return &iamv1.LogoutResponse{}, nil
}

// Snapshot returns a copy of the login history and the number of remaining sessions.
func (s *AuthService) Snapshot() (logins []string, remaining int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.logins), len(s.tokens)
}
