package iamclient

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

const (
	authnSealed  = "v1.Zm9vYmFy+/=.sealed-by-vws-iam.é☃ tail"
	assumeSealed = "v1.YXNzdW1lZA==.another-sealed-value"
)

func assumedRoleAuthn() *iamv1.AuthenticateResponse {
	arn := "arn:vws:sts::123456789012:assumed-role/ops/s1"
	return &iamv1.AuthenticateResponse{
		Account: "123456789012", Arn: arn,
		Principal: &iamv1.Principal{
			Type: iamv1.PrincipalType_PRINCIPAL_TYPE_ASSUMED_ROLE, Arn: arn, Project: "123456789012",
			UniqueId: "AROAOPS:s1", Resource: "projects/123456789012/roles/ops", SessionName: "s1",
			SessionContext: authnSealed,
		},
	}
}

func describeAs(p iam.Principal) iam.Request {
	return iam.Request{Principal: p, Action: "ec2:DescribeVpcs", Resource: "*"}
}

// vws-iam denies an assumed role whose Authorize principal lacks the
// session_context it sealed. A signed request through the real verifier, and
// the principal AssumeRole returned, both reach Authorize with it unchanged.
func TestSessionContextReachesAuthorizeByteForByte(t *testing.T) {
	c, s := harness(t)
	s.authnResult = assumedRoleAuthn()
	s.assumedCtx = assumeSealed
	now := time.Now().UTC()
	v := sigv4.NewVerifier(sigv4.Verifier{
		Service: sigv4.ServiceEC2, Region: resource.RegionName,
		Now: func() time.Time { return now }, Auth: iam.Authenticator(c),
	})
	body := strings.NewReader("Action=DescribeVpcs&Version=2016-11-15")
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://127.0.0.1:8081/", body)
	req.Host = "127.0.0.1:8081"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	cred := sigv4.Credential{AccessKey: "ASIAOPS", Secret: "unused-by-the-fake", Account: account(t)}
	if err := sigv4.Sign(req, cred, sigv4.ServiceEC2, resource.RegionName, now); err != nil {
		t.Fatal(err)
	}
	caller, err := v.Verify(req)
	if err != nil {
		t.Fatal(err)
	}
	if err := iam.Check(t.Context(), c, caller, "ec2:DescribeVpcs", "*"); err != nil {
		t.Fatal(err)
	}
	p := s.authz[0].GetPrincipal()
	if got := p.GetSessionContext(); got != authnSealed {
		t.Errorf("Authorize session_context %q, want %q from Authenticate", got, authnSealed)
	}
	if p.GetType() != iamv1.PrincipalType_PRINCIPAL_TYPE_ASSUMED_ROLE {
		t.Errorf("principal type %v", p.GetType())
	}

	bob, err := c.Authenticate(t.Context(), signed)
	if err != nil {
		t.Fatal(err)
	}
	role, err := c.AssumeRole(t.Context(), bob, "arn:vws:iam::123456789012:role/ops", "s1", 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Authorize(t.Context(), describeAs(role.Key.Principal)); err != nil {
		t.Fatal(err)
	}
	if got := s.authz[len(s.authz)-1].GetPrincipal().GetSessionContext(); got != assumeSealed {
		t.Errorf("Authorize session_context %q, want %q from AssumeRole", got, assumeSealed)
	}
}

// A user principal has no session_context, and Authorize gets none: an empty
// field is what vws-iam expects from a user or root.
func TestUserPrincipalSendsNoSessionContext(t *testing.T) {
	c, s := harness(t)
	bob, err := c.Authenticate(t.Context(), signed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Authorize(t.Context(), describeAs(bob)); err != nil {
		t.Fatal(err)
	}
	if got := s.authz[0].GetPrincipal().GetSessionContext(); got != "" {
		t.Errorf("user session_context %q", got)
	}
}

// The sealed value travels only in the Authorize request: no client log
// record, span, error or formatted principal holds it.
func TestSessionContextIsNeverLoggedOrTraced(t *testing.T) {
	rec := spanRecorder()
	before := len(rec.Ended())
	var buf bytes.Buffer
	c, s := harness(t)
	c.SetLogger(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	s.authnResult = assumedRoleAuthn()
	s.assumedCtx = assumeSealed
	p, err := c.Authenticate(t.Context(), signed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Authorize(t.Context(), describeAs(p)); err != nil {
		t.Fatal(err)
	}
	role, err := c.AssumeRole(t.Context(), p, "arn:vws:iam::123456789012:role/ops", "s2", 0)
	if err != nil {
		t.Fatal(err)
	}
	s.decision = iamv1.Decision_DECISION_DENY_EXPLICIT
	rp := role.Key.Principal
	caller := resource.Caller{Account: rp.Account, Principal: rp.ARN, Root: rp.Root, Ref: rp.Ref}
	err = iam.Check(t.Context(), c, caller, "ec2:RunInstances", "*")
	if resource.CodeOf(err) != resource.CodePermissionDenied {
		t.Fatalf("explicit deny: %v", err)
	}
	buf.WriteString(err.Error())
	slog.New(slog.NewJSONHandler(&buf, nil)).InfoContext(t.Context(), "caller",
		slog.Any("principal", p), slog.Any("role", rp), slog.Any("ref", rp.Ref))
	slog.New(slog.NewTextHandler(&buf, nil)).InfoContext(t.Context(), "caller",
		slog.Any("principal", p), slog.Any("ref", rp.Ref))
	for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
		for _, v := range []any{p, role, caller, rp.Ref} {
			fmt.Fprintf(&buf, format, v)
		}
	}
	for _, sp := range rec.Ended()[before:] {
		buf.WriteString(sp.Name() + sp.Status().Description)
		for _, kv := range sp.Attributes() {
			buf.WriteString(string(kv.Key) + "=" + kv.Value.String())
		}
		for _, ev := range sp.Events() {
			buf.WriteString(ev.Name)
			for _, kv := range ev.Attributes {
				buf.WriteString(kv.Value.String())
			}
		}
	}
	for _, sealed := range []string{authnSealed, assumeSealed} {
		if strings.Contains(buf.String(), sealed) {
			t.Errorf("session_context %q appears in a log, span, error or formatted value:\n%s", sealed, buf.String())
		}
	}
	if !strings.Contains(buf.String(), "AROAOPS:s1") || !strings.Contains(buf.String(), `"SessionContext":"[REDACTED]"`) {
		t.Errorf("formatted principal lost its unique id or the redaction marker:\n%s", buf.String())
	}
}
