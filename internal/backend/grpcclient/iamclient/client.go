// Package iamclient is the vws-iam client: AuthService Authenticate and
// Authorize, console sessions (Login, ValidateSession, Logout) and STS
// AssumeRole over vws.iam.v1 gRPC (vws-proto v0.3.0).
package iamclient

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

// Call limits.
const (
	// CallTimeout bounds one attempt when the caller's context has no
	// earlier deadline.
	CallTimeout = 5 * time.Second
	// MaxAttempts bounds retries on UNAVAILABLE of the calls that are safe
	// to repeat: Authenticate, Authorize, ValidateSession and Logout (revoking
	// a revoked session is a no-op). Login and AssumeRole are tried once: a
	// retry could count a failed password twice or mint a second session.
	MaxAttempts = 3
)

// Options tune the client. The zero value is the production setting.
type Options struct {
	// Backoff is the first retry delay; it doubles per attempt. Zero is 50ms.
	Backoff time.Duration
}

// Client implements the per-request half of iam.Client, AssumeRole and the
// policy and virtual MFA device tag calls of iam.Admin.
type Client struct {
	auth       iamv1.AuthServiceClient
	tokens     iamv1.TokenServiceClient
	policies   iamv1.PolicyServiceClient
	mfaDevices iamv1.MfaDeviceServiceClient
	backoff    time.Duration
	close      func() error
}

// Dial connects to vws-iam at target. The connection is lazy; the first call
// dials. Transport security is the cluster network's, as for the other
// backends.
func Dial(target string) (*Client, error) {
	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("dial vws-iam %s: %w", target, err)
	}
	c := New(conn, Options{})
	c.close = conn.Close
	return c, nil
}

// New wraps an existing connection.
func New(conn grpc.ClientConnInterface, o Options) *Client {
	if o.Backoff <= 0 {
		o.Backoff = 50 * time.Millisecond
	}
	return &Client{
		auth: iamv1.NewAuthServiceClient(conn), tokens: iamv1.NewTokenServiceClient(conn),
		policies: iamv1.NewPolicyServiceClient(conn), mfaDevices: iamv1.NewMfaDeviceServiceClient(conn),
		backoff: o.Backoff, close: func() error { return nil },
	}
}

// Close closes a connection Dial opened.
func (c *Client) Close() error { return c.close() }

// call runs one attempt under CallTimeout.
func call[Req, Resp any](ctx context.Context, fn func(context.Context, Req, ...grpc.CallOption) (Resp, error), req Req) (Resp, error) {
	ctx, cancel := context.WithTimeout(ctx, CallTimeout)
	defer cancel()
	return fn(ctx, req)
}

// retry runs a call that is safe to repeat up to MaxAttempts times while vws-iam is
// UNAVAILABLE, with doubling backoff, and never past ctx.
func retry[Req, Resp any](ctx context.Context, backoff time.Duration, fn func(context.Context, Req, ...grpc.CallOption) (Resp, error), req Req) (Resp, error) {
	var resp Resp
	var err error
	for attempt := 1; ; attempt++ {
		resp, err = call(ctx, fn, req)
		if status.Code(err) != codes.Unavailable || attempt == MaxAttempts {
			return resp, err
		}
		t := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			t.Stop()
			return resp, err
		case <-t.C:
		}
		backoff *= 2
	}
}

// Authenticate implements iam.Client: vws-iam checks the signature with the
// secret it holds and names the principal.
func (c *Client) Authenticate(ctx context.Context, r sigv4.AuthRequest) (iam.Principal, error) {
	req := &iamv1.AuthenticateRequest{
		AccessKeyId: r.AccessKeyID, Date: r.Date, Region: r.Region, Service: string(r.Service),
		CanonicalRequest: r.CanonicalRequest, StringToSign: r.StringToSign, Signature: r.Signature,
		SessionToken: r.SessionToken, SourceIp: r.SourceIP,
	}
	resp, err := retry(ctx, c.backoff, c.auth.Authenticate, req)
	if err != nil {
		return iam.Principal{}, authError(err)
	}
	account, err := resource.Parse[resource.AccountID](resp.GetAccount())
	if err != nil {
		return iam.Principal{}, fmt.Errorf("vws-iam Authenticate returned account %q: %w", resp.GetAccount(), err)
	}
	proof, err := proto.Marshal(req)
	if err != nil {
		return iam.Principal{}, fmt.Errorf("serialize AuthenticateRequest: %w", err)
	}
	p := iam.Principal{Account: account, ARN: resp.GetArn(), Root: resp.GetIsRoot()}
	p.Ref = refOf(resp.GetPrincipal())
	p.Ref.ProofKind, p.Ref.Proof = resource.ProofSigV4, string(proof)
	return p, nil
}

func refOf(pr *iamv1.Principal) resource.PrincipalRef {
	ref := resource.PrincipalRef{UniqueID: pr.GetUniqueId(), Resource: pr.GetResource(), SessionName: pr.GetSessionName(), MFA: pr.GetMfaAuthenticated()}
	if pr.GetAuthTime() != nil {
		ref.AuthTime = pr.GetAuthTime().AsTime()
	}
	return ref
}

// principalProto is the vws-iam Principal for p. Type comes from the ARN;
// a root's unique id is its project, as vws-iam expects.
func principalProto(p iam.Principal) *iamv1.Principal {
	out := &iamv1.Principal{
		Arn: p.ARN, Project: p.Account.String(), UniqueId: p.Ref.UniqueID, Resource: p.Ref.Resource,
		SessionName: p.Ref.SessionName, MfaAuthenticated: p.Ref.MFA,
	}
	if !p.Ref.AuthTime.IsZero() {
		out.AuthTime = timestamppb.New(p.Ref.AuthTime)
	}
	switch {
	case p.Root:
		out.Type = iamv1.PrincipalType_PRINCIPAL_TYPE_ROOT
		if out.UniqueId == "" {
			out.UniqueId = out.Project
		}
	case strings.Contains(p.ARN, ":assumed-role/"):
		out.Type = iamv1.PrincipalType_PRINCIPAL_TYPE_ASSUMED_ROLE
	default:
		out.Type = iamv1.PrincipalType_PRINCIPAL_TYPE_USER
	}
	return out
}

// Authorize implements iam.Client. "*" is sent as no resources, the proto's
// spelling of it; anything but DECISION_ALLOW is a deny.
func (c *Client) Authorize(ctx context.Context, r iam.Request) (iam.Decision, error) {
	req := &iamv1.AuthorizeRequest{Principal: principalProto(r.Principal), Action: r.Action}
	if r.Resource != "" && r.Resource != "*" {
		req.Resources = []string{r.Resource}
	}
	if len(r.Context) > 0 {
		req.Context = make(map[string]*iamv1.ContextValues, len(r.Context))
		for k, v := range r.Context {
			req.Context[k] = &iamv1.ContextValues{Values: []string{v}}
		}
	}
	resp, err := retry(ctx, c.backoff, c.auth.Authorize, req)
	if err != nil {
		return iam.Decision{}, authError(err)
	}
	switch resp.GetDecision() {
	case iamv1.Decision_DECISION_ALLOW:
		return iam.Decision{Allowed: true, Reason: resp.GetReason()}, nil
	case iamv1.Decision_DECISION_DENY_EXPLICIT:
		return iam.Decision{Explicit: true, Reason: resp.GetReason()}, nil
	case iamv1.Decision_DECISION_DENY_IMPLICIT, iamv1.Decision_DECISION_UNSPECIFIED:
		return iam.Decision{Reason: resp.GetReason()}, nil
	default:
		return iam.Decision{Reason: "unknown decision " + resp.GetDecision().String()}, nil
	}
}

// AssumeRole implements STS AssumeRole over vws-iam TokenService. vws-iam
// takes the caller only from the request's authentication oneof and verifies
// it itself: a SigV4 caller sends the AuthenticateRequest it authenticated
// with, a console session caller its session token. Nothing goes in gRPC
// metadata and the deprecated caller field is never set. A caller with no
// vws-iam credential (the static root key) is refused without a call, as AWS
// refuses root. Not retried: it issues credentials.
func (c *Client) AssumeRole(ctx context.Context, caller iam.Principal, roleARN, session string, duration time.Duration) (iam.AssumedRole, error) {
	role, err := roleResource(roleARN)
	if err != nil {
		return iam.AssumedRole{}, err
	}
	req := &iamv1.AssumeRoleRequest{Role: role, RoleSessionName: session, DurationSeconds: int32(duration / time.Second)} //nolint:gosec // the surface bounds duration to 900..43200s.
	switch caller.Ref.ProofKind {
	case resource.ProofSigV4:
		var sig iamv1.AuthenticateRequest
		if err := proto.Unmarshal([]byte(caller.Ref.Proof), &sig); err != nil {
			return iam.AssumedRole{}, resource.Unauthenticated("caller credential unreadable")
		}
		req.Authentication = &iamv1.AssumeRoleRequest_Sigv4{Sigv4: &sig}
	case resource.ProofSession:
		req.Authentication = &iamv1.AssumeRoleRequest_ConsoleSessionToken{ConsoleSessionToken: caller.Ref.Proof}
	default:
		if caller.Root {
			return iam.AssumedRole{}, resource.Denied("Roles may not be assumed by root accounts.")
		}
		return iam.AssumedRole{}, resource.Unauthenticated("caller has no vws-iam credential")
	}
	resp, err := call(ctx, c.tokens.AssumeRole, req)
	if err != nil {
		return iam.AssumedRole{}, authError(err)
	}
	p, err := principalOf(resp.GetAssumedRoleUser())
	if err != nil {
		return iam.AssumedRole{}, err
	}
	cr := resp.GetCredentials()
	return iam.AssumedRole{
		Key: iam.Key{
			AccessKey: cr.GetAccessKeyId(), Secret: cr.GetSecretAccessKey(), SessionToken: cr.GetSessionToken(),
			Expires: cr.GetExpireTime().AsTime(), Principal: p,
		},
		AssumedRoleID: resp.GetAssumedRoleUser().GetUniqueId(), ARN: p.ARN,
	}, nil
}

// roleResource turns arn:vws:iam::{project}:role{path}{name} into
// projects/{project}/roles/{name}.
func roleResource(arn string) (string, error) {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[2] != "iam" || !strings.HasPrefix(parts[5], "role/") {
		return "", resource.Invalid("roleArn", "not a role ARN")
	}
	if _, err := resource.Parse[resource.AccountID](parts[4]); err != nil {
		return "", resource.Invalid("roleArn", "not a role ARN")
	}
	name := parts[5][strings.LastIndex(parts[5], "/")+1:]
	if name == "" {
		return "", resource.Invalid("roleArn", "not a role ARN")
	}
	return "projects/" + parts[4] + "/roles/" + name, nil
}

// authError maps a vws-iam status to the errors the surfaces already speak.
// The AWS code travels in ErrorInfo metadata aws_code.
func authError(err error) error {
	st, ok := status.FromError(err)
	if !ok {
		return err
	}
	aws := ""
	for _, d := range st.Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok {
			aws = info.GetMetadata()["aws_code"]
		}
	}
	switch st.Code() { //nolint:exhaustive // every other code is "unavailable" below.
	case codes.Unauthenticated:
		switch aws {
		case "InvalidClientTokenId":
			return sigv4.ErrUnknownKey
		case "ExpiredToken":
			return resource.Unauthenticated("the security token included in the request is expired")
		case "RequestTimeTooSkewed":
			return resource.Unauthenticated("request time is outside the allowed window")
		case "IncompleteSignature":
			return resource.Unauthenticated("credential scope rejected")
		case "MissingAuthenticationToken":
			return resource.Unauthenticated("missing signature")
		default:
			return resource.Unauthenticated("signature mismatch")
		}
	case codes.PermissionDenied:
		return resource.Denied(st.Message())
	case codes.NotFound:
		return &resource.Error{Code: resource.CodeNotFound, Message: st.Message()}
	case codes.InvalidArgument:
		return &resource.Error{Code: resource.CodeInvalidArgument, Message: st.Message()}
	case codes.ResourceExhausted:
		return &resource.Error{Code: resource.CodeResourceExhausted, Message: st.Message()}
	default:
		// Unavailable, deadline, internal: the surfaces answer "unavailable"
		// without echoing vws-iam's message.
		return fmt.Errorf("vws-iam: %w", errors.New(st.Code().String()))
	}
}
