package iamclient

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	longrunningpb "cloud.google.com/go/longrunning/autogen/longrunningpb"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

var authTime = time.Date(2026, 10, 14, 7, 0, 0, 0, time.UTC)

// server is a fake vws-iam AuthService and TokenService that records what it
// was sent, with which metadata, and whether a deadline was set.
type server struct {
	iamv1.UnimplementedAuthServiceServer
	iamv1.UnimplementedTokenServiceServer
	iamv1.UnimplementedPolicyServiceServer
	iamv1.UnimplementedMfaDeviceServiceServer
	iamv1.UnimplementedRoleServiceServer
	mu          sync.Mutex
	authn       []*iamv1.AuthenticateRequest
	authz       []*iamv1.AuthorizeRequest
	assume      []*iamv1.AssumeRoleRequest
	md          []metadata.MD
	noDeadline  int
	failFirst   int // answer this many calls with UNAVAILABLE first
	authnErr    error
	decision    iamv1.Decision
	authnResult *iamv1.AuthenticateResponse
	assumeErr   error
	login       []*iamv1.LoginRequest
	validate    []*iamv1.ValidateSessionRequest
	logout      []*iamv1.LogoutRequest
	sessions    sessionServer // nil: Login, ValidateSession, Logout are unimplemented
	// sent records every request message, to prove what left console-api.
	sent []proto.Message
	// Policy tag calls.
	tagPolicy    []*iamv1.TagPolicyRequest
	untagPolicy  []*iamv1.UntagPolicyRequest
	listTags     []*iamv1.ListPolicyTagsRequest
	tagErr       error
	tagPolicyRes *longrunningpb.Operation
	listTagsRes  *iamv1.ListPolicyTagsResponse
	getPolicy    []*iamv1.GetPolicyRequest
	getPolicyRes *iamv1.Policy
	getPolicyErr error
	// Policy version calls.
	updatePolicy    []*iamv1.UpdatePolicyRequest
	updateErr       error
	updateRes       *longrunningpb.Operation
	listVersions    []*iamv1.ListPolicyVersionsRequest
	listVersionsRes *iamv1.ListPolicyVersionsResponse
	listVersionsErr error
	// Virtual MFA device tag calls.
	tagMfa        []*iamv1.TagMFADeviceRequest
	untagMfa      []*iamv1.UntagMFADeviceRequest
	listMfaTags   []*iamv1.ListMFADeviceTagsRequest
	mfaTagErr     error
	tagMfaRes     *longrunningpb.Operation
	listMfaTagRes *iamv1.ListMFADeviceTagsResponse
	getMfa        []*iamv1.GetMfaDeviceRequest
	getMfaRes     *iamv1.MfaDevice
	getMfaErr     error
	// Role calls.
	getRole       []*iamv1.GetRoleRequest
	getRoleRes    *iamv1.Role
	getRoleErr    error
	updateRole    []*iamv1.UpdateRoleRequest
	updateRoleRes *longrunningpb.Operation
	updateRoleErr error
}

func (s *server) GetRole(ctx context.Context, req *iamv1.GetRoleRequest) (*iamv1.Role, error) {
	if err := s.enter(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.getRole = append(s.getRole, req)
	if s.getRoleErr != nil {
		return nil, s.getRoleErr
	}
	return s.getRoleRes, nil
}

func (s *server) UpdateRole(ctx context.Context, req *iamv1.UpdateRoleRequest) (*longrunningpb.Operation, error) {
	if err := s.enter(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.updateRole = append(s.updateRole, req)
	if s.updateRoleErr != nil {
		return nil, s.updateRoleErr
	}
	return s.updateRoleRes, nil
}

func (s *server) GetPolicy(ctx context.Context, req *iamv1.GetPolicyRequest) (*iamv1.Policy, error) {
	if err := s.enter(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.getPolicy = append(s.getPolicy, req)
	if s.getPolicyErr != nil {
		return nil, s.getPolicyErr
	}
	if s.getPolicyRes != nil {
		return s.getPolicyRes, nil
	}
	return &iamv1.Policy{Name: req.GetName(), Status: &iamv1.PolicyStatus{Arn: policyARN}}, nil
}

func (s *server) UpdatePolicy(ctx context.Context, req *iamv1.UpdatePolicyRequest) (*longrunningpb.Operation, error) {
	if err := s.enter(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.updatePolicy = append(s.updatePolicy, req)
	if s.updateErr != nil {
		return nil, s.updateErr
	}
	if s.updateRes != nil {
		return s.updateRes, nil
	}
	return &longrunningpb.Operation{Done: true}, nil
}

func (s *server) ListPolicyVersions(
	ctx context.Context, req *iamv1.ListPolicyVersionsRequest,
) (*iamv1.ListPolicyVersionsResponse, error) {
	if err := s.enter(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.listVersions = append(s.listVersions, req)
	if s.listVersionsErr != nil {
		return nil, s.listVersionsErr
	}
	return s.listVersionsRes, nil
}

func (s *server) TagPolicy(ctx context.Context, req *iamv1.TagPolicyRequest) (*longrunningpb.Operation, error) {
	if err := s.enter(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tagPolicy = append(s.tagPolicy, req)
	if s.tagErr != nil {
		return nil, s.tagErr
	}
	if s.tagPolicyRes != nil {
		return s.tagPolicyRes, nil
	}
	return &longrunningpb.Operation{Done: true}, nil
}

func (s *server) UntagPolicy(ctx context.Context, req *iamv1.UntagPolicyRequest) (*longrunningpb.Operation, error) {
	if err := s.enter(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.untagPolicy = append(s.untagPolicy, req)
	if s.tagErr != nil {
		return nil, s.tagErr
	}
	return &longrunningpb.Operation{Done: true}, nil
}

func (s *server) ListPolicyTags(
	ctx context.Context, req *iamv1.ListPolicyTagsRequest,
) (*iamv1.ListPolicyTagsResponse, error) {
	if err := s.enter(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.listTags = append(s.listTags, req)
	if s.tagErr != nil {
		return nil, s.tagErr
	}
	return s.listTagsRes, nil
}

func (s *server) GetMfaDevice(ctx context.Context, req *iamv1.GetMfaDeviceRequest) (*iamv1.MfaDevice, error) {
	if err := s.enter(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.getMfa = append(s.getMfa, req)
	if s.getMfaErr != nil {
		return nil, s.getMfaErr
	}
	if s.getMfaRes != nil {
		return s.getMfaRes, nil
	}
	return &iamv1.MfaDevice{
		Name:   req.GetName(),
		Status: &iamv1.MfaDeviceStatus{SerialNumber: mfaSerial},
	}, nil
}

func (s *server) TagMFADevice(ctx context.Context, req *iamv1.TagMFADeviceRequest) (*longrunningpb.Operation, error) {
	if err := s.enter(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tagMfa = append(s.tagMfa, req)
	if s.mfaTagErr != nil {
		return nil, s.mfaTagErr
	}
	if s.tagMfaRes != nil {
		return s.tagMfaRes, nil
	}
	return &longrunningpb.Operation{Done: true}, nil
}

func (s *server) UntagMFADevice(
	ctx context.Context, req *iamv1.UntagMFADeviceRequest,
) (*longrunningpb.Operation, error) {
	if err := s.enter(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.untagMfa = append(s.untagMfa, req)
	if s.mfaTagErr != nil {
		return nil, s.mfaTagErr
	}
	return &longrunningpb.Operation{Done: true}, nil
}

func (s *server) ListMFADeviceTags(
	ctx context.Context, req *iamv1.ListMFADeviceTagsRequest,
) (*iamv1.ListMFADeviceTagsResponse, error) {
	if err := s.enter(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.listMfaTags = append(s.listMfaTags, req)
	if s.mfaTagErr != nil {
		return nil, s.mfaTagErr
	}
	return s.listMfaTagRes, nil
}

func (s *server) enter(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := ctx.Deadline(); !ok {
		s.noDeadline++
	}
	md, _ := metadata.FromIncomingContext(ctx)
	s.md = append(s.md, md)
	if s.failFirst > 0 {
		s.failFirst--
		return status.Error(codes.Unavailable, "warming up")
	}
	return nil
}

func (s *server) Authenticate(ctx context.Context, req *iamv1.AuthenticateRequest) (*iamv1.AuthenticateResponse, error) {
	if err := s.enter(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authn = append(s.authn, req)
	if s.authnErr != nil {
		return nil, s.authnErr
	}
	return s.authnResult, nil
}

func (s *server) Authorize(ctx context.Context, req *iamv1.AuthorizeRequest) (*iamv1.AuthorizeResponse, error) {
	if err := s.enter(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authz = append(s.authz, req)
	return &iamv1.AuthorizeResponse{Decision: s.decision, Reason: "because"}, nil
}

func (s *server) AssumeRole(ctx context.Context, req *iamv1.AssumeRoleRequest) (*iamv1.AssumeRoleResponse, error) {
	if err := s.enter(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.assume = append(s.assume, req)
	if s.assumeErr != nil {
		return nil, s.assumeErr
	}
	return &iamv1.AssumeRoleResponse{
		Credentials: &iamv1.Credentials{AccessKeyId: "ASIAABCDEFGHIJKLMNOP", SecretAccessKey: "s3cr3t", SessionToken: "tok", ExpireTime: timestamppb.New(authTime.Add(time.Hour))},
		AssumedRoleUser: &iamv1.Principal{
			Type: iamv1.PrincipalType_PRINCIPAL_TYPE_ASSUMED_ROLE, Arn: "arn:vws:sts::123456789012:assumed-role/ops/s1",
			Project: "123456789012", UniqueId: "AROAOPS:s1", Resource: "projects/123456789012/roles/ops", SessionName: "s1",
		},
	}, nil
}

func awsErr(code codes.Code, reason, aws string) error {
	st, err := status.New(code, aws).WithDetails(&errdetails.ErrorInfo{Reason: reason, Domain: "vws.dev", Metadata: map[string]string{"aws_code": aws}})
	if err != nil {
		panic(err)
	}
	return st.Err()
}

func harness(t *testing.T) (*Client, *server) {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	s := &server{decision: iamv1.Decision_DECISION_ALLOW, authnResult: &iamv1.AuthenticateResponse{
		Account: "123456789012", Arn: "arn:vws:iam::123456789012:user/eng/bob",
		Principal: &iamv1.Principal{
			Type: iamv1.PrincipalType_PRINCIPAL_TYPE_USER, Arn: "arn:vws:iam::123456789012:user/eng/bob", Project: "123456789012",
			UniqueId: "AIDABOB", Resource: "projects/123456789012/users/bob", MfaAuthenticated: true, AuthTime: timestamppb.New(authTime),
		},
	}}
	g := grpc.NewServer(grpc.UnaryInterceptor(func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
		if m, ok := req.(proto.Message); ok {
			s.mu.Lock()
			s.sent = append(s.sent, proto.Clone(m))
			s.mu.Unlock()
		}
		return h(ctx, req)
	}))
	iamv1.RegisterAuthServiceServer(g, s)
	iamv1.RegisterTokenServiceServer(g, s)
	iamv1.RegisterPolicyServiceServer(g, s)
	iamv1.RegisterMfaDeviceServiceServer(g, s)
	iamv1.RegisterRoleServiceServer(g, s)
	go func() { _ = g.Serve(lis) }()
	t.Cleanup(g.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return New(conn, Options{Backoff: time.Millisecond}), s
}

var signed = sigv4.AuthRequest{
	AccessKeyID: "AKIABOB", Date: "20261014", Region: "vws-1", Service: sigv4.ServiceEC2,
	CanonicalRequest: "POST\n/\n\nhost:x\n\nhost\nabc", StringToSign: "AWS4-HMAC-SHA256\n20261014T070000Z\n20261014/vws-1/ec2/aws4_request\nabc",
	Signature: "deadbeef", SessionToken: "", SourceIP: "192.0.2.7",
}

func TestAuthenticateMapsEveryFieldAndThePrincipal(t *testing.T) {
	c, s := harness(t)
	p, err := c.Authenticate(t.Context(), signed)
	if err != nil {
		t.Fatal(err)
	}
	want := &iamv1.AuthenticateRequest{
		AccessKeyId: "AKIABOB", Date: "20261014", Region: "vws-1", Service: "ec2",
		CanonicalRequest: signed.CanonicalRequest, StringToSign: signed.StringToSign, Signature: "deadbeef", SourceIp: "192.0.2.7",
	}
	if len(s.authn) != 1 || !proto.Equal(s.authn[0], want) {
		t.Fatalf("sent %v, want %v", s.authn, want)
	}
	if p.Account.String() != "123456789012" || p.ARN != "arn:vws:iam::123456789012:user/eng/bob" || p.Root {
		t.Errorf("principal %+v", p)
	}
	ref := p.Ref
	if ref.UniqueID != "AIDABOB" || ref.Resource != "projects/123456789012/users/bob" || !ref.MFA || !ref.AuthTime.Equal(authTime) || ref.ProofKind != resource.ProofSigV4 {
		t.Errorf("ref %+v", ref)
	}
	var proof iamv1.AuthenticateRequest
	if err := proto.Unmarshal([]byte(ref.Proof), &proof); err != nil || !proto.Equal(&proof, want) {
		t.Errorf("proof is not the serialized AuthenticateRequest: %v", err)
	}
	if s.noDeadline != 0 {
		t.Errorf("%d calls had no deadline", s.noDeadline)
	}
}

func TestAuthenticateErrors(t *testing.T) {
	for _, tc := range []struct {
		err   error
		check func(error) bool
	}{
		{awsErr(codes.Unauthenticated, "INVALID_CREDENTIALS", "InvalidClientTokenId"), func(e error) bool { return errors.Is(e, sigv4.ErrUnknownKey) }},
		{awsErr(codes.Unauthenticated, "INVALID_CREDENTIALS", "SignatureDoesNotMatch"), func(e error) bool {
			re := resource.AsError(e)
			return re != nil && re.Code == resource.CodeUnauthenticated && re.Message == "signature mismatch"
		}},
		{awsErr(codes.Unauthenticated, "TOKEN_EXPIRED", "ExpiredToken"), func(e error) bool {
			re := resource.AsError(e)
			return re != nil && re.Code == resource.CodeUnauthenticated && re.Message == "the security token included in the request is expired"
		}},
		{awsErr(codes.Unauthenticated, "INVALID_CREDENTIALS", "RequestTimeTooSkewed"), func(e error) bool {
			re := resource.AsError(e)
			return re != nil && re.Code == resource.CodeUnauthenticated && re.Message == "request time is outside the allowed window"
		}},
		// Anything else is not a *resource.Error, so the verifier answers
		// "authentication unavailable" without vws-iam's message.
		{status.Error(codes.Internal, "boom"), func(e error) bool {
			var re *resource.Error
			return e != nil && !errors.As(e, &re) && !errors.Is(e, sigv4.ErrUnknownKey)
		}},
	} {
		c, s := harness(t)
		s.authnErr = tc.err
		_, err := c.Authenticate(t.Context(), signed)
		if !tc.check(err) {
			t.Errorf("%v -> %v", tc.err, err)
		}
	}
}

func TestAuthenticateRetriesTransientFailuresBounded(t *testing.T) {
	c, s := harness(t)
	s.failFirst = 2
	if _, err := c.Authenticate(t.Context(), signed); err != nil {
		t.Fatalf("after two UNAVAILABLE: %v", err)
	}
	c, s = harness(t)
	s.failFirst = 100
	if _, err := c.Authenticate(t.Context(), signed); err == nil {
		t.Fatal("never-available server succeeded")
	}
	if len(s.md) != MaxAttempts {
		t.Errorf("%d attempts, want %d", len(s.md), MaxAttempts)
	}
}

func TestAuthorizeMapsPrincipalResourcesContextAndDecision(t *testing.T) {
	c, s := harness(t)
	bob, err := c.Authenticate(t.Context(), signed)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		decision          iamv1.Decision
		allowed, explicit bool
	}{
		{iamv1.Decision_DECISION_ALLOW, true, false},
		{iamv1.Decision_DECISION_DENY_EXPLICIT, false, true},
		{iamv1.Decision_DECISION_DENY_IMPLICIT, false, false},
		{iamv1.Decision_DECISION_UNSPECIFIED, false, false},
	} {
		s.decision = tc.decision
		d, err := c.Authorize(t.Context(), iam.Request{Principal: bob, Action: "s3:GetObject", Resource: "arn:vws:s3:::b/k", Context: map[string]string{"aws:SourceIp": "192.0.2.7"}})
		if err != nil || d.Allowed != tc.allowed || d.Explicit != tc.explicit {
			t.Errorf("%v: %+v %v", tc.decision, d, err)
		}
	}
	got := s.authz[0]
	want := &iamv1.AuthorizeRequest{
		Principal: &iamv1.Principal{
			Type: iamv1.PrincipalType_PRINCIPAL_TYPE_USER, Arn: "arn:vws:iam::123456789012:user/eng/bob", Project: "123456789012",
			UniqueId: "AIDABOB", Resource: "projects/123456789012/users/bob", MfaAuthenticated: true, AuthTime: timestamppb.New(authTime),
		},
		Action: "s3:GetObject", Resources: []string{"arn:vws:s3:::b/k"},
		Context: map[string]*iamv1.ContextValues{"aws:SourceIp": {Values: []string{"192.0.2.7"}}},
	}
	if !proto.Equal(got, want) {
		t.Errorf("sent %v\nwant %v", got, want)
	}
	if _, err := c.Authorize(t.Context(), iam.Request{Principal: bob, Action: "ec2:DescribeVpcs", Resource: "*"}); err != nil {
		t.Fatal(err)
	}
	if r := s.authz[len(s.authz)-1].GetResources(); len(r) != 0 {
		t.Errorf("\"*\" should be sent as no resources (the proto's \"*\"), got %q", r)
	}
}

func TestPrincipalTypes(t *testing.T) {
	for _, tc := range []struct {
		p    iam.Principal
		want iamv1.PrincipalType
	}{
		{iam.Principal{ARN: "arn:vws:iam::123456789012:root", Root: true}, iamv1.PrincipalType_PRINCIPAL_TYPE_ROOT},
		{iam.Principal{ARN: "arn:vws:iam::123456789012:user/bob"}, iamv1.PrincipalType_PRINCIPAL_TYPE_USER},
		{iam.Principal{ARN: "arn:vws:sts::123456789012:assumed-role/ops/s1"}, iamv1.PrincipalType_PRINCIPAL_TYPE_ASSUMED_ROLE},
	} {
		if got := principalProto(tc.p).GetType(); got != tc.want {
			t.Errorf("%s: %v", tc.p.ARN, got)
		}
	}
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	root := principalProto(iam.Principal{Account: account, ARN: "arn:vws:iam::123456789012:root", Root: true})
	if root.GetUniqueId() != "123456789012" || root.GetProject() != "123456789012" {
		t.Errorf("root unique_id must be the project, as vws-iam rechecks: %v", root)
	}
}

// A signed request through the real verifier: the principal vws-iam named
// reaches Authorize intact, so vws-iam's recheck can pass.
func TestVerifierToAuthorizeKeepsThePrincipal(t *testing.T) {
	c, s := harness(t)
	now := time.Now().UTC()
	v := sigv4.NewVerifier(sigv4.Verifier{Service: sigv4.ServiceEC2, Region: resource.RegionName, Now: func() time.Time { return now }, Auth: iam.Authenticator(c)})
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://127.0.0.1:8081/", strings.NewReader("Action=DescribeVpcs&Version=2016-11-15"))
	req.Host = "127.0.0.1:8081"
	req.RemoteAddr = "192.0.2.9:1234"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := sigv4.Sign(req, sigv4.Credential{AccessKey: "AKIABOB", Secret: "unused-by-the-fake", Account: account}, sigv4.ServiceEC2, resource.RegionName, now); err != nil {
		t.Fatal(err)
	}
	caller, err := v.Verify(req)
	if err != nil {
		t.Fatal(err)
	}
	if err := iam.Check(t.Context(), c, caller, "ec2:DescribeVpcs", "*"); err != nil {
		t.Fatal(err)
	}
	if got := s.authn[0].GetSourceIp(); got != "192.0.2.9" {
		t.Errorf("source_ip %q", got)
	}
	p := s.authz[0].GetPrincipal()
	if p.GetUniqueId() != "AIDABOB" || p.GetResource() != "projects/123456789012/users/bob" || p.GetType() != iamv1.PrincipalType_PRINCIPAL_TYPE_USER || !p.GetMfaAuthenticated() {
		t.Errorf("principal at Authorize %v", p)
	}
	s.decision = iamv1.Decision_DECISION_DENY_EXPLICIT
	if err := iam.Check(t.Context(), c, caller, "ec2:DescribeVpcs", "*"); resource.CodeOf(err) != resource.CodePermissionDenied {
		t.Errorf("explicit deny: %v", err)
	}
}
