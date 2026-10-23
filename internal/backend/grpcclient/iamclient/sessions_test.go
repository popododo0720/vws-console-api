package iamclient

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-console-api/internal/backend/backendtest"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

// sessionServer is the console sign-in half of the fake vws-iam.
type sessionServer interface {
	Login(context.Context, *iamv1.LoginRequest) (*iamv1.LoginResponse, error)
	ValidateSession(context.Context, *iamv1.ValidateSessionRequest) (*iamv1.ValidateSessionResponse, error)
	Logout(context.Context, *iamv1.LogoutRequest) (*iamv1.LogoutResponse, error)
}

func (s *server) Login(ctx context.Context, req *iamv1.LoginRequest) (*iamv1.LoginResponse, error) {
	if err := s.enter(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.login = append(s.login, req)
	ss := s.sessions
	s.mu.Unlock()
	if ss == nil {
		return nil, status.Error(codes.Unimplemented, "Login")
	}
	return ss.Login(ctx, req)
}

func (s *server) ValidateSession(ctx context.Context, req *iamv1.ValidateSessionRequest) (*iamv1.ValidateSessionResponse, error) {
	if err := s.enter(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.validate = append(s.validate, req)
	ss := s.sessions
	s.mu.Unlock()
	if ss == nil {
		return nil, status.Error(codes.Unimplemented, "ValidateSession")
	}
	return ss.ValidateSession(ctx, req)
}

func (s *server) Logout(ctx context.Context, req *iamv1.LogoutRequest) (*iamv1.LogoutResponse, error) {
	if err := s.enter(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.logout = append(s.logout, req)
	ss := s.sessions
	s.mu.Unlock()
	if ss == nil {
		return nil, status.Error(codes.Unimplemented, "Logout")
	}
	return ss.Logout(ctx, req)
}

// stubSessions answers every call with fixed results.
type stubSessions struct {
	login    *iamv1.LoginResponse
	loginErr error
	valid    *iamv1.ValidateSessionResponse
	validErr error
	outErr   error
	block    bool // wait for the deadline
}

func (st *stubSessions) wait(ctx context.Context) error {
	if st.block {
		<-ctx.Done()
		return status.Error(codes.DeadlineExceeded, "slow")
	}
	return nil
}

func (st *stubSessions) Login(ctx context.Context, _ *iamv1.LoginRequest) (*iamv1.LoginResponse, error) {
	if err := st.wait(ctx); err != nil {
		return nil, err
	}
	return st.login, st.loginErr
}

func (st *stubSessions) ValidateSession(ctx context.Context, _ *iamv1.ValidateSessionRequest) (*iamv1.ValidateSessionResponse, error) {
	if err := st.wait(ctx); err != nil {
		return nil, err
	}
	return st.valid, st.validErr
}

func (st *stubSessions) Logout(ctx context.Context, _ *iamv1.LogoutRequest) (*iamv1.LogoutResponse, error) {
	if err := st.wait(ctx); err != nil {
		return nil, err
	}
	if st.outErr != nil {
		return nil, st.outErr
	}
	return &iamv1.LogoutResponse{}, nil
}

var (
	expires  = time.Date(2026, 10, 14, 19, 0, 0, 0, time.UTC)
	bobProto = &iamv1.Principal{
		Type: iamv1.PrincipalType_PRINCIPAL_TYPE_USER, Arn: "arn:vws:iam::123456789012:user/bob", Project: "123456789012",
		UniqueId: "AIDABOB", Resource: "projects/123456789012/users/bob", MfaAuthenticated: true, AuthTime: timestamppb.New(authTime),
	}
)

func account(t *testing.T) resource.AccountID {
	t.Helper()
	a, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// fakeLoginMessage is the uniform sign-in failure the in-memory IAM answers.
func fakeLoginMessage(t *testing.T) string {
	t.Helper()
	_, err := iam.NewFake().Login(t.Context(), iam.LoginRequest{Account: account(t), UserName: "nobody", Password: "wrong password 1"})
	re := resource.AsError(err)
	if re == nil || re.Code != resource.CodeUnauthenticated {
		t.Fatalf("fake login failure %v", err)
	}
	return re.Message
}

func TestLoginMapsTheRequestAndTheSession(t *testing.T) {
	c, s := harness(t)
	s.sessions = &stubSessions{login: &iamv1.LoginResponse{SessionToken: "sess-1", ExpireTime: timestamppb.New(expires), Principal: bobProto}}
	got, err := c.Login(t.Context(), iam.LoginRequest{Account: account(t), UserName: "bob", Password: "correct horse 1", MFACode: "123456", SourceIP: "198.51.100.4"})
	if err != nil {
		t.Fatal(err)
	}
	want := &iamv1.LoginRequest{Project: "123456789012", UserName: "bob", Password: "correct horse 1", TotpCode: "123456", SourceIp: "198.51.100.4"}
	if len(s.login) != 1 || !proto.Equal(s.login[0], want) {
		t.Fatalf("sent %v, want %v", s.login, want)
	}
	if got.Token != "sess-1" || !got.Expires.Equal(expires) || got.Principal.ARN != bobProto.Arn || got.Principal.Account.String() != "123456789012" || got.Principal.Root {
		t.Errorf("session %+v", got)
	}
	if got.Principal.Ref.UniqueID != "AIDABOB" || got.Principal.Ref.Resource != bobProto.Resource || !got.Principal.Ref.MFA {
		t.Errorf("ref %+v", got.Principal.Ref)
	}
	if s.noDeadline != 0 {
		t.Errorf("%d calls had no deadline", s.noDeadline)
	}
	root := &iamv1.Principal{Type: iamv1.PrincipalType_PRINCIPAL_TYPE_ROOT, Arn: "arn:vws:iam::123456789012:root", Project: "123456789012", UniqueId: "123456789012"}
	s.sessions = &stubSessions{login: &iamv1.LoginResponse{SessionToken: "sess-r", ExpireTime: timestamppb.New(expires), Principal: root}}
	if got, err := c.Login(t.Context(), iam.LoginRequest{Account: account(t), UserName: "root", Password: "pw"}); err != nil || !got.Principal.Root {
		t.Errorf("root session %+v %v", got, err)
	}
}

func TestLoginErrorsMatchTheFake(t *testing.T) {
	uniform := fakeLoginMessage(t)
	for _, tc := range []struct {
		name  string
		err   error
		code  resource.Code
		msg   string
		busy  bool
		calls int
	}{
		{"wrong password", awsErr(codes.Unauthenticated, "INVALID_CREDENTIALS", "InvalidClientTokenId"), resource.CodeUnauthenticated, uniform, false, 1},
		{"mfa required", awsErr(codes.Unauthenticated, "MFA_REQUIRED", "AccessDenied"), resource.CodeUnauthenticated, uniform, false, 1},
		{"disabled user", status.Error(codes.PermissionDenied, "user bob is disabled"), resource.CodeUnauthenticated, uniform, false, 1},
		{"unknown project", status.Error(codes.NotFound, "project 123456789012"), resource.CodeUnauthenticated, uniform, false, 1},
		{"bad field", status.Error(codes.InvalidArgument, "user_name"), resource.CodeUnauthenticated, uniform, false, 1},
		{"rate limited", status.Error(codes.ResourceExhausted, "slow down"), resource.CodeResourceExhausted, "", false, 1},
		// Login has side effects (a session, lockout counters): not retried.
		{"busy", status.Error(codes.Unavailable, "hashing slots full"), resource.CodeUnavailable, "", true, 1},
		{"internal", status.Error(codes.Internal, "db password=hunter2"), resource.CodeUnavailable, "", false, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, s := harness(t)
			s.sessions = &stubSessions{loginErr: tc.err}
			_, err := c.Login(t.Context(), iam.LoginRequest{Account: account(t), UserName: "bob", Password: "pw"})
			re := resource.AsError(err)
			if re == nil || re.Code != tc.code {
				t.Fatalf("got %v, want code %v", err, tc.code)
			}
			if tc.msg != "" && re.Message != tc.msg {
				t.Errorf("message %q, want the uniform %q", re.Message, tc.msg)
			}
			if strings.Contains(err.Error(), "hunter2") || strings.Contains(err.Error(), "disabled") {
				t.Errorf("vws-iam's message leaked: %v", err)
			}
			if iam.IsBusy(err) != tc.busy {
				t.Errorf("busy %v, want %v", iam.IsBusy(err), tc.busy)
			}
			if len(s.login) != tc.calls {
				t.Errorf("%d Login calls, want %d", len(s.login), tc.calls)
			}
		})
	}
}

func TestLoginTransportFailureFailsClosed(t *testing.T) {
	c, err := Dial("127.0.0.1:1") // nothing listens
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	_, err = c.Login(ctx, iam.LoginRequest{Account: account(t), UserName: "bob", Password: "pw"})
	if resource.CodeOf(err) != resource.CodeUnavailable {
		t.Errorf("login: %v", err)
	}
	if _, err := c.ValidateSession(ctx, "tok"); resource.CodeOf(err) != resource.CodeUnavailable {
		t.Errorf("validate: %v", err)
	}
	if err := c.Logout(ctx, "tok"); resource.CodeOf(err) != resource.CodeUnavailable {
		t.Errorf("logout: %v", err)
	}
}

// The console must not hand out a session vws-iam marks for a forced
// password change: there is no reset flow yet, so sign-in is refused and the
// session revoked.
func TestLoginRefusesPasswordResetRequired(t *testing.T) {
	c, s := harness(t)
	s.sessions = &stubSessions{login: &iamv1.LoginResponse{SessionToken: "sess-1", ExpireTime: timestamppb.New(expires), Principal: bobProto, PasswordResetRequired: true}}
	got, err := c.Login(t.Context(), iam.LoginRequest{Account: account(t), UserName: "bob", Password: "pw"})
	if resource.CodeOf(err) != resource.CodePermissionDenied || got.Token != "" {
		t.Fatalf("got %+v %v", got, err)
	}
	if len(s.logout) != 1 || s.logout[0].GetSessionToken() != "sess-1" {
		t.Errorf("session not revoked: %v", s.logout)
	}
}

func TestValidateSessionAndLogout(t *testing.T) {
	c, s := harness(t)
	st := &stubSessions{valid: &iamv1.ValidateSessionResponse{Principal: bobProto, ExpireTime: timestamppb.New(expires)}}
	s.sessions = st
	got, err := c.ValidateSession(t.Context(), "sess-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Token != "" || got.Principal.ARN != bobProto.Arn || !got.Expires.Equal(expires) {
		t.Errorf("session %+v", got)
	}
	ref := got.Principal.Ref
	if ref.UniqueID != "AIDABOB" || ref.ProofKind != resource.ProofSession || ref.Proof != "sess-1" {
		t.Errorf("ref %+v", ref)
	}
	if len(s.validate) != 1 || s.validate[0].GetSessionToken() != "sess-1" {
		t.Errorf("sent %v", s.validate)
	}

	for _, e := range []error{
		awsErr(codes.Unauthenticated, "TOKEN_EXPIRED", "ExpiredToken"),
		awsErr(codes.Unauthenticated, "INVALID_CREDENTIALS", "InvalidClientTokenId"),
	} {
		st.validErr = e
		if _, err := c.ValidateSession(t.Context(), "sess-1"); resource.CodeOf(err) != resource.CodeUnauthenticated {
			t.Errorf("%v -> %v", e, err)
		}
	}
	st.validErr = status.Error(codes.Internal, "boom")
	if _, err := c.ValidateSession(t.Context(), "sess-1"); resource.CodeOf(err) != resource.CodeUnavailable {
		t.Errorf("internal -> %v (must fail closed)", err)
	}
	st.validErr = nil
	st.valid = &iamv1.ValidateSessionResponse{Principal: &iamv1.Principal{Project: "not-a-project"}}
	if _, err := c.ValidateSession(t.Context(), "sess-1"); err == nil {
		t.Error("a malformed principal was accepted")
	}

	if err := c.Logout(t.Context(), "sess-1"); err != nil || len(s.logout) != 1 || s.logout[0].GetSessionToken() != "sess-1" {
		t.Errorf("logout %v %v", err, s.logout)
	}
	st.outErr = awsErr(codes.Unauthenticated, "INVALID_CREDENTIALS", "InvalidClientTokenId")
	if err := c.Logout(t.Context(), "gone"); err != nil {
		t.Errorf("logout of an unknown token must succeed: %v", err)
	}
	st.outErr = status.Error(codes.Internal, "boom")
	if err := c.Logout(t.Context(), "sess-1"); resource.CodeOf(err) != resource.CodeUnavailable {
		t.Errorf("logout internal -> %v", err)
	}
}

func TestSessionCallsUseTheRequestDeadline(t *testing.T) {
	c, s := harness(t)
	s.sessions = &stubSessions{block: true}
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := c.Login(ctx, iam.LoginRequest{Account: account(t), UserName: "bob", Password: "pw"})
	if resource.CodeOf(err) != resource.CodeUnavailable {
		t.Errorf("login past the deadline: %v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Errorf("took %v: the request deadline was not used", time.Since(start))
	}
	if s.noDeadline != 0 {
		t.Errorf("%d calls had no deadline", s.noDeadline)
	}
}

// fakeSessions serves Login, ValidateSession and Logout from an in-memory
// iam.Fake, translating its errors to vws-iam statuses, so the same contract
// runs on the fake directly and through the gRPC client.
type fakeSessions struct{ f *iam.Fake }

func toStatus(err error) error {
	if iam.IsBusy(err) {
		return status.Error(codes.Unavailable, "busy")
	}
	switch resource.CodeOf(err) { //nolint:exhaustive // the rest are Internal below.
	case resource.CodeUnauthenticated:
		return awsErr(codes.Unauthenticated, "INVALID_CREDENTIALS", "InvalidClientTokenId")
	case resource.CodeResourceExhausted:
		return status.Error(codes.ResourceExhausted, "slow down")
	default:
		return status.Error(codes.Internal, err.Error())
	}
}

func protoOf(p iam.Principal) *iamv1.Principal {
	return &iamv1.Principal{Type: iamv1.PrincipalType_PRINCIPAL_TYPE_USER, Arn: p.ARN, Project: p.Account.String(), UniqueId: "AIDA" + p.ARN[strings.LastIndex(p.ARN, "/")+1:]}
}

func (fs fakeSessions) Login(ctx context.Context, r *iamv1.LoginRequest) (*iamv1.LoginResponse, error) {
	a, err := resource.Parse[resource.AccountID](r.GetProject())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "project")
	}
	s, err := fs.f.Login(ctx, iam.LoginRequest{Account: a, UserName: r.GetUserName(), Password: r.GetPassword(), MFACode: r.GetTotpCode(), SourceIP: r.GetSourceIp()})
	if err != nil {
		return nil, toStatus(err)
	}
	return &iamv1.LoginResponse{SessionToken: s.Token, ExpireTime: timestamppb.New(s.Expires), Principal: protoOf(s.Principal)}, nil
}

func (fs fakeSessions) ValidateSession(ctx context.Context, r *iamv1.ValidateSessionRequest) (*iamv1.ValidateSessionResponse, error) {
	s, err := fs.f.ValidateSession(ctx, r.GetSessionToken())
	if err != nil {
		return nil, toStatus(err)
	}
	return &iamv1.ValidateSessionResponse{Principal: protoOf(s.Principal), ExpireTime: timestamppb.New(s.Expires)}, nil
}

func (fs fakeSessions) Logout(ctx context.Context, r *iamv1.LogoutRequest) (*iamv1.LogoutResponse, error) {
	if err := fs.f.Logout(ctx, r.GetSessionToken()); err != nil {
		return nil, toStatus(err)
	}
	return &iamv1.LogoutResponse{}, nil
}

func seededFake(t *testing.T) *iam.Fake {
	t.Helper()
	f := iam.NewFake()
	if _, err := f.CreateUser(t.Context(), account(t), "bob", "/"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.CreateLoginProfile(
		t.Context(), account(t), "bob", "correct horse 1", backendtest.UserGrant(t.Context(), t, f, account(t), "bob"),
	); err != nil {
		t.Fatal(err)
	}
	return f
}

// sessionsContract is what the console surface relies on from any
// iam.Sessions: one uniform 401 for every bad sign-in, a usable session,
// revocation, and an idempotent Logout.
func sessionsContract(t *testing.T, s iam.Sessions) {
	t.Helper()
	ctx := t.Context()
	uniform := fakeLoginMessage(t)
	for _, bad := range []iam.LoginRequest{
		{Account: account(t), UserName: "bob", Password: "wrong password 1", SourceIP: "192.0.2.1"},
		{Account: account(t), UserName: "nobody", Password: "correct horse 1", SourceIP: "192.0.2.1"},
	} {
		_, err := s.Login(ctx, bad)
		if re := resource.AsError(err); re == nil || re.Code != resource.CodeUnauthenticated || re.Message != uniform {
			t.Errorf("%s: %v", bad.UserName, err)
		}
	}
	sess, err := s.Login(ctx, iam.LoginRequest{Account: account(t), UserName: "bob", Password: "correct horse 1", SourceIP: "192.0.2.1"})
	if err != nil || sess.Token == "" || sess.Principal.ARN != "arn:vws:iam::123456789012:user/bob" || !sess.Expires.After(time.Now()) {
		t.Fatalf("login %+v %v", sess, err)
	}
	got, err := s.ValidateSession(ctx, sess.Token)
	if err != nil || got.Principal.ARN != sess.Principal.ARN || got.Token != "" {
		t.Errorf("validate %+v %v", got, err)
	}
	if err := s.Logout(ctx, sess.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ValidateSession(ctx, sess.Token); resource.CodeOf(err) != resource.CodeUnauthenticated {
		t.Errorf("validate after logout: %v", err)
	}
	if err := s.Logout(ctx, sess.Token); err != nil {
		t.Errorf("second logout: %v", err)
	}
}

func TestSessionsContract(t *testing.T) {
	t.Run("fake", func(t *testing.T) { sessionsContract(t, seededFake(t)) })
	t.Run("grpc", func(t *testing.T) {
		c, s := harness(t)
		s.sessions = fakeSessions{seededFake(t)}
		sessionsContract(t, c)
	})
}

func TestAssumeRoleSendsTheCallersAuthentication(t *testing.T) {
	c, s := harness(t)
	bob, err := c.Authenticate(t.Context(), signed)
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.AssumeRole(t.Context(), bob, "arn:vws:iam::123456789012:role/eng/ops", "s1", 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.assume) != 1 {
		t.Fatalf("%d AssumeRole calls", len(s.assume))
	}
	req := s.assume[0]
	if req.GetRole() != "projects/123456789012/roles/ops" || req.GetRoleSessionName() != "s1" || req.GetDurationSeconds() != 1800 {
		t.Errorf("request %v", req)
	}
	if req.GetCaller() != nil { //nolint:staticcheck // asserting the deprecated field stays unset.
		t.Error("the deprecated caller field was sent")
	}
	if !proto.Equal(req.GetSigv4(), s.authn[0]) {
		t.Errorf("sigv4 %v, want the caller's AuthenticateRequest %v", req.GetSigv4(), s.authn[0])
	}
	if got.ARN != "arn:vws:sts::123456789012:assumed-role/ops/s1" || got.AssumedRoleID != "AROAOPS:s1" ||
		got.Key.AccessKey != "ASIAABCDEFGHIJKLMNOP" || got.Key.Secret != "s3cr3t" || got.Key.SessionToken != "tok" ||
		!got.Key.Expires.Equal(authTime.Add(time.Hour)) || got.Key.Principal.ARN != got.ARN || got.Key.Principal.Account.String() != "123456789012" {
		t.Errorf("assumed role %+v", got)
	}

	// A console session caller sends its session token instead.
	s.sessions = &stubSessions{valid: &iamv1.ValidateSessionResponse{Principal: bobProto, ExpireTime: timestamppb.New(expires)}}
	sess, err := c.ValidateSession(t.Context(), "sess-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.AssumeRole(t.Context(), sess.Principal, "arn:vws:iam::123456789012:role/ops", "s2", 0); err != nil {
		t.Fatal(err)
	}
	if tok := s.assume[1].GetConsoleSessionToken(); tok != "sess-1" || s.assume[1].GetSigv4() != nil || s.assume[1].GetDurationSeconds() != 0 {
		t.Errorf("session caller sent %v", s.assume[1])
	}

	for _, md := range s.md {
		for k := range md {
			if strings.HasPrefix(k, "x-vws-") {
				t.Errorf("caller metadata %q sent: the caller goes in the request", k)
			}
		}
	}
}

func TestAssumeRoleWithoutAVWSIAMCredentialMakesNoCall(t *testing.T) {
	c, s := harness(t)
	root := iam.Principal{Account: account(t), ARN: "arn:vws:iam::123456789012:root", Root: true}
	if _, err := c.AssumeRole(t.Context(), root, "arn:vws:iam::123456789012:role/ops", "s1", 0); resource.CodeOf(err) != resource.CodePermissionDenied {
		t.Errorf("static root: %v", err)
	}
	user := iam.Principal{Account: account(t), ARN: "arn:vws:iam::123456789012:user/bob"}
	if _, err := c.AssumeRole(t.Context(), user, "arn:vws:iam::123456789012:role/ops", "s1", 0); resource.CodeOf(err) != resource.CodeUnauthenticated {
		t.Errorf("no proof: %v", err)
	}
	bob, err := c.Authenticate(t.Context(), signed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.AssumeRole(t.Context(), bob, "not-an-arn", "s1", 0); resource.CodeOf(err) != resource.CodeInvalidArgument {
		t.Errorf("bad role arn: %v", err)
	}
	if len(s.assume) != 0 {
		t.Errorf("%d AssumeRole calls", len(s.assume))
	}
}

func TestAssumeRoleErrorsAndNoRetry(t *testing.T) {
	c, s := harness(t)
	bob, err := c.Authenticate(t.Context(), signed)
	if err != nil {
		t.Fatal(err)
	}
	s.assumeErr = awsErr(codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied")
	if _, err := c.AssumeRole(t.Context(), bob, "arn:vws:iam::123456789012:role/ops", "s1", 0); resource.CodeOf(err) != resource.CodePermissionDenied {
		t.Errorf("denied: %v", err)
	}
	s.assumeErr = status.Error(codes.Unavailable, "down")
	if _, err := c.AssumeRole(t.Context(), bob, "arn:vws:iam::123456789012:role/ops", "s1", 0); err == nil {
		t.Error("unavailable succeeded")
	}
	if len(s.assume) != 2 {
		t.Errorf("%d AssumeRole calls: STS issues credentials and is not retried", len(s.assume))
	}
}

// The access-key secret signs the request inside the client and never leaves
// console-api: nothing sent to vws-iam, and nothing kept on the caller,
// contains it.
func TestSecretsNeverLeaveConsoleAPI(t *testing.T) {
	const secret = "wJalrXUtnFEMI-K7MDENG-bPxRfiCYEXAMPLEKEY"
	c, s := harness(t)
	now := time.Now().UTC()
	v := sigv4.NewVerifier(sigv4.Verifier{Service: sigv4.ServiceEC2, Region: resource.RegionName, Now: func() time.Time { return now }, Auth: iam.Authenticator(c)})
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://127.0.0.1:8081/", strings.NewReader("Action=DescribeVpcs&Version=2016-11-15"))
	req.Host = "127.0.0.1:8081"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := sigv4.Sign(req, sigv4.Credential{AccessKey: "AKIABOB", Secret: secret, Account: account(t)}, sigv4.ServiceEC2, resource.RegionName, now); err != nil {
		t.Fatal(err)
	}
	caller, err := v.Verify(req)
	if err != nil {
		t.Fatal(err)
	}
	if err := iam.Check(t.Context(), c, caller, "ec2:DescribeVpcs", "*"); err != nil {
		t.Fatal(err)
	}
	p := iam.Principal{Account: caller.Account, ARN: caller.Principal, Root: caller.Root, Ref: caller.Ref}
	if _, err := c.AssumeRole(t.Context(), p, "arn:vws:iam::123456789012:role/ops", "s1", 0); err != nil {
		t.Fatal(err)
	}
	if len(s.sent) < 3 {
		t.Fatalf("only %d messages recorded", len(s.sent))
	}
	for _, m := range s.sent {
		b, err := proto.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(b, []byte(secret)) || strings.Contains(prototext.Format(m), secret) {
			t.Errorf("%T carries the secret", m)
		}
	}
	if strings.Contains(caller.Ref.Proof, secret) {
		t.Error("the caller's proof carries the secret")
	}
}
