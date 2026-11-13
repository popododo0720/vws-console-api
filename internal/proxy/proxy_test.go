package proxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/admin/store"
	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

type fixture struct {
	p                     *Proxy
	stsCalls, originCalls int
	stsBody               string
	status                int
	registry              *store.Registry
	dir                   string
	stsHost               string
	stsForms              []url.Values
}

func setup(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{status: 200, dir: t.TempDir(), registry: store.New(store.NewMemory())}
	_, err := f.registry.AWSAccounts().Create(context.Background(), store.AWSAccount{
		ID: "123456789012", RoleARN: "arn:aws:iam::123456789012:role/inventory", AllowedRegions: []string{"us-east-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.registry.Projects().Put(t.Context(), store.Project{
		Project: "123456789012", AWSAccounts: []string{"123456789012"},
	}); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(f.dir, "aws-external-id-123456789012"), []byte("external-canary"), 0o600)
	source := sigv4.Credential{AccessKey: "source-canary-key", Secret: "source-canary-secret"}
	session := sigv4.Credential{
		AccessKey: "session-canary-key", Secret: "session-canary-secret",
		SessionToken: "session-token",
	}
	checkSignature := func(r *http.Request, c sigv4.Credential, service sigv4.Service) {
		t.Helper()
		account, err := resource.Parse[resource.AccountID]("123456789012")
		if err != nil {
			t.Fatal(err)
		}
		c.Account = account
		v := sigv4.NewVerifier(sigv4.Verifier{
			Service: service, Now: f.p.now, Regions: backend.NewStaticRegions(nil, []backend.AWSAccount{
				{ID: "123456789012", AllowedRegions: []string{"us-east-1"}},
			}),
			Auth: sigv4.Lookup(func(_ context.Context, key string) (sigv4.Credential, bool) {
				return c, key == c.AccessKey
			}),
		})
		if _, err := v.Verify(r); err != nil {
			t.Errorf("origin received an invalid signature: %v", err)
		}
	}
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.stsCalls++
		checkSignature(r, source, sigv4.ServiceSTS)
		r.ParseForm()
		f.stsForms = append(f.stsForms, r.Form)
		h := sha256.Sum256([]byte("principal"))
		if r.Form.Get("DurationSeconds") != "3600" ||
			!strings.HasSuffix(r.Form.Get("RoleSessionName"), fmt.Sprintf("-%x", h[:16])) {
			t.Error("incorrect AssumeRole parameters")
		}
		if f.stsBody != "" {
			fmt.Fprint(w, f.stsBody)
			return
		}
		fmt.Fprintf(w, `<AssumeRoleResponse><AssumeRoleResult><Credentials><AccessKeyId>%s</AccessKeyId>`+
			`<SecretAccessKey>%s</SecretAccessKey><SessionToken>%s</SessionToken><Expiration>%s</Expiration>`+
			`</Credentials></AssumeRoleResult></AssumeRoleResponse>`, session.AccessKey, session.Secret,
			session.SessionToken, f.p.now().Add(time.Hour).UTC().Format(time.RFC3339))
	}))
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.originCalls++
		if r.Header.Get("X-Amz-Security-Token") != session.SessionToken || r.Header.Get("X-Vws-Account") != "" {
			t.Error("token was not replaced or forwarding metadata leaked")
		}
		checkSignature(r, session, sigv4.ServiceEC2)
		w.Header().Set("X-Origin", "preserved")
		w.WriteHeader(f.status)
		fmt.Fprint(w, "<DescribeInstancesResponse/>")
	}))
	f.stsHost = strings.TrimPrefix(sts.URL, "http://")
	t.Cleanup(sts.Close)
	t.Cleanup(origin.Close)
	accounts := RegistryAccounts{Registry: f.registry, CredentialDirectory: f.dir}
	f.p, err = New(accounts, source, sts.URL, "us-east-1", origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := f.p.transport.(*http.Transport)
	if !ok {
		t.Fatal("unexpected transport")
	}
	t.Cleanup(transport.CloseIdleConnections)
	return f
}

func (f *fixture) request(raw string) *httptest.ResponseRecorder {
	return f.requestAs(raw, "principal", "us-east-1")
}

func (f *fixture) requestAs(raw, principal, region string) *httptest.ResponseRecorder {
	return f.requestProject(raw, principal, region, "123456789012")
}

func (f *fixture) requestProject(raw, principal, region, project string) *httptest.ResponseRecorder {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/", strings.NewReader(raw))
	for k, v := range map[string]string{
		"X-Vws-Account": project, "X-Vws-Principal": principal,
		"X-Vws-Target-Region": region, "X-Vws-Target-Service": "ec2", "X-Amz-Security-Token": "old-token",
	} {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	f.p.ServeHTTP(w, r)
	return w
}

func TestResignCacheAndExpiry(t *testing.T) {
	f := setup(t)
	now := time.Now()
	f.p.now = func() time.Time { return now }
	for range 2 {
		w := f.request("Action=DescribeInstances&Version=2016-11-15")
		if w.Code != 200 || w.Body.String() != "<DescribeInstancesResponse/>" || w.Header().Get("X-Origin") != "preserved" {
			t.Fatalf("unexpected response: %d %s", w.Code, w.Body.String())
		}
	}
	if f.stsCalls != 1 || f.originCalls != 2 {
		t.Fatal("cache missed")
	}
	if f.stsForms[0].Get("ExternalId") != "external-canary" ||
		f.stsForms[0].Get("RoleArn") != "arn:aws:iam::123456789012:role/inventory" ||
		!strings.HasPrefix(f.stsForms[0].Get("RoleSessionName"), "vws-123456789012-") {
		t.Fatal("incorrect AssumeRole binding")
	}
	now = now.Add(55 * time.Minute)
	f.request("Action=DescribeInstances")
	if f.stsCalls != 2 {
		t.Fatal("expired cache was reused")
	}
	clear(f.p.cache)
	f.request("Action=DescribeInstances")
	if f.stsCalls != 3 {
		t.Fatal("restart did not acquire new credentials")
	}
}

// TestAssumeRoleSignsForTheSTSRegion checks that STS is signed for its own
// endpoint's region, not the EC2 region of the request.
func TestAssumeRoleSignsForTheSTSRegion(t *testing.T) {
	f := setup(t)
	for _, region := range []string{"", "US-EAST-1", "us-east-1/x", "global"} {
		if _, err := New(f.p.accounts, f.p.source, f.p.sts, region, f.p.origin); err == nil {
			t.Errorf("STS region %q was accepted", region)
		}
	}
	v, err := f.registry.AWSAccounts().Get(context.Background(), "123456789012")
	if err != nil {
		t.Fatal(err)
	}
	v.AllowedRegions = append(v.AllowedRegions, "ap-northeast-2")
	if _, err := f.registry.AWSAccounts().Update(context.Background(), v); err != nil {
		t.Fatal(err)
	}
	base := f.p.transport
	var stsScope string
	f.p.transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == f.stsHost {
			stsScope = r.Header.Get("Authorization")
			return base.RoundTrip(r)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Header: http.Header{}, Request: r}, nil
	})
	if w := f.requestAs("Action=DescribeInstances", "principal", "ap-northeast-2"); w.Code != 200 {
		t.Fatalf("got %d", w.Code)
	}
	if !strings.Contains(stsScope, "/us-east-1/sts/aws4_request") {
		t.Fatalf("AssumeRole was signed for %q", stsScope)
	}
}

// TestSlowAssumeRoleDelaysNoCachedRequest checks that the cache lock is not
// held across the STS call.
func TestSlowAssumeRoleDelaysNoCachedRequest(t *testing.T) {
	f := setup(t)
	if w := f.request("Action=DescribeInstances"); w.Code != 200 {
		t.Fatalf("got %d", w.Code)
	}
	base := f.p.transport
	started, release := make(chan struct{}), make(chan struct{})
	f.p.transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == f.stsHost {
			close(started)
			<-release
			return &http.Response{StatusCode: http.StatusBadRequest, Body: http.NoBody, Header: http.Header{}, Request: r}, nil
		}
		return base.RoundTrip(r)
	})
	slow := make(chan int)
	go func() { slow <- f.requestAs("Action=DescribeInstances", "slow", "us-east-1").Code }()
	<-started
	cached := make(chan int)
	go func() { cached <- f.request("Action=DescribeInstances").Code }()
	select {
	case code := <-cached:
		if code != 200 {
			t.Errorf("cached request got %d", code)
		}
	case <-time.After(5 * time.Second):
		t.Error("a cached request waited for another principal's AssumeRole")
	}
	close(release)
	<-slow
}

func TestAccountIDIsBoundedBeforeTheFilesystem(t *testing.T) {
	f := setup(t)
	accounts := RegistryAccounts{Registry: f.registry, CredentialDirectory: f.dir}
	const long = "1234567890123"
	if _, err := f.registry.AWSAccounts().Create(context.Background(), store.AWSAccount{
		ID: long, RoleARN: "arn:aws:iam::" + long + ":role/inventory", AllowedRegions: []string{"us-east-1"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.dir, "aws-external-id-"+long), []byte("external-canary"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"", "12345678901", "1234567890123", "12345678901a", "../123456789", "12345678901\x00"} {
		if _, err := accounts.Account(context.Background(), id, "us-east-1"); err == nil {
			t.Errorf("account %q was accepted", id)
		}
	}
	if _, err := accounts.Account(context.Background(), "123456789012", "us-east-1"); err != nil {
		t.Fatal(err)
	}
}

func TestDeniedNeverCallsOutbound(t *testing.T) {
	for _, raw := range []string{
		"Action=RunScheduledInstances", "Action=ModifyInstanceAttribute", "Action=DeleteVolume",
		"Action=CreateSnapshots", "Action=DeleteTagsExtra", "Action=Describe", "Action=Describe%00Instances",
		"Action=%zz", "Action=DescribeInstances&Action=RunInstances", "Action=DescribeInstances;Action=RunInstances",
		"Action=DescribeInstances&X-Amz-Credential=evil", "", "Action=DescribeInstances&Filter=1&Filter=2",
	} {
		t.Run(raw, func(t *testing.T) {
			f := setup(t)
			if w := f.request(raw); w.Code != 403 || !strings.Contains(w.Body.String(), "<Code>UnauthorizedOperation</Code>") {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			if f.stsCalls != 0 || f.originCalls != 0 {
				t.Fatal("denied request made an outbound call")
			}
		})
	}
}

func TestMutationAllowlist(t *testing.T) {
	for _, action := range []string{
		"RunInstances", "StartInstances", "StopInstances", "RebootInstances", "TerminateInstances",
		"CreateSnapshot", "DeleteSnapshot", "CreateTags", "DeleteTags",
	} {
		t.Run(action, func(t *testing.T) {
			f := setup(t)
			if w := f.request("Action=" + action); w.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			if f.stsCalls != 1 || f.originCalls != 1 {
				t.Fatalf("STS=%d origin=%d", f.stsCalls, f.originCalls)
			}
		})
	}
}

func TestMissingExternalIDAndChangedRegistration(t *testing.T) {
	f := setup(t)
	os.Remove(filepath.Join(f.dir, "aws-external-id-123456789012"))
	if f.request("Action=DescribeInstances").Code != 403 || f.stsCalls != 0 {
		t.Fatal("missing ExternalId accepted")
	}
	os.WriteFile(filepath.Join(f.dir, "aws-external-id-123456789012"), []byte("external-canary"), 0o600)
	f.request("Action=DescribeInstances")
	a, _ := f.registry.AWSAccounts().Get(context.Background(), "123456789012")
	a.AllowedRegions = nil
	f.registry.AWSAccounts().Update(context.Background(), a)
	if f.request("Action=DescribeInstances").Code != 403 || f.originCalls != 1 {
		t.Fatal("stale registration accepted")
	}
}

func TestMisleadingSuccessAndOriginErrors(t *testing.T) {
	f := setup(t)
	f.stsBody = "<AssumeRoleResponse/>"
	if f.request("Action=DescribeInstances").Code != 502 || f.originCalls != 0 {
		t.Fatal("empty STS success accepted")
	}
	f.stsBody = ""
	f.status = 503
	if f.request("Action=DescribeInstances").Code != 503 || f.originCalls != 3 {
		t.Fatal("upstream failure hidden or not retried")
	}
}

func TestAmbiguousWriteRetries(t *testing.T) {
	for _, action := range []string{
		"CreateSnapshot", "RebootInstances", "DescribeInstances", "RunInstances", "RunInstances&ClientToken=stable",
		"StartInstances", "StopInstances", "TerminateInstances", "CreateTags", "DeleteTags", "DeleteSnapshot",
	} {
		for _, status := range []int{0, 500, 429} {
			t.Run(fmt.Sprintf("%s/%d", action, status), func(t *testing.T) {
				f := setup(t)
				f.status = status
				base, attempts := f.p.transport, 0
				f.p.transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
					if r.URL.Host != f.stsHost {
						attempts++
						if status == 0 {
							return nil, fmt.Errorf("ambiguous transport failure")
						}
					}
					return base.RoundTrip(r)
				})
				w := f.request("Action=" + action)
				want := 3
				if status != 429 && (action == "CreateSnapshot" || action == "RebootInstances" || action == "RunInstances") {
					want = 1
				}
				if attempts != want || status != 0 && w.Code != status || status == 0 && w.Code != 502 {
					t.Fatalf("attempts=%d want=%d status=%d", attempts, want, w.Code)
				}
			})
		}
	}
}

func TestCredentialsNeverLogged(t *testing.T) {
	f := setup(t)
	var logs bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	canary := "source-canary-key source-canary-secret session-token external-canary"
	f.stsBody = canary
	w := f.request("Action=DescribeInstances")
	t.Setenv("CREDENTIALS_DIRECTORY", f.dir)
	os.WriteFile(filepath.Join(f.dir, "aws-source"), []byte(canary), 0o600)
	_, err := SourceCredential()
	output := logs.String() + w.Body.String() + fmt.Sprint(err)
	for _, secret := range strings.Fields(canary) {
		if strings.Contains(output, secret) {
			t.Fatal("credential appeared in logs or errors")
		}
	}
	for _, key := range []string{"AKIAIOSFODNN7EXAMPLE", "AKIDEXAMPLE", "default", ""} {
		data := []byte(fmt.Sprintf(`{"AccessKey":%q,"Secret":"safe-value"}`, key))
		os.WriteFile(filepath.Join(f.dir, "aws-source"), data, 0o600)
		if _, err := SourceCredential(); err == nil {
			t.Fatal("default credential accepted")
		}
	}
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	t.Setenv("AWS_ACCESS_KEY_ID", "environment-key")
	if _, err := SourceCredential(); err == nil {
		t.Fatal("environment credential accepted")
	}
}

func TestEndpointBoundary(t *testing.T) {
	f := setup(t)
	for _, endpoint := range []string{
		"http://192.0.2.1", "https://user:secret@localhost", "https://localhost/?Action=RunInstances",
	} {
		if _, err := New(f.p.accounts, f.p.source, endpoint, "us-east-1", f.p.origin); err == nil {
			t.Fatal("unsafe endpoint accepted")
		}
	}
	f.p.transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("source-canary-secret")
	})
	if w := f.request("Action=DescribeInstances"); w.Code != 502 || strings.Contains(w.Body.String(), "canary") {
		t.Fatal("transport error leaked")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestMetadataAndBodyBoundary(t *testing.T) {
	for _, header := range []string{
		"X-Vws-Account", "X-Vws-Principal", "X-Vws-Target-Region", "X-Vws-Target-Service",
	} {
		t.Run(header, func(t *testing.T) {
			f := setup(t)
			r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/?Action=DescribeInstances", nil)
			for k, v := range map[string]string{
				"X-Vws-Account": "123456789012", "X-Vws-Principal": "principal",
				"X-Vws-Target-Region": "us-east-1", "X-Vws-Target-Service": "ec2",
			} {
				r.Header.Set(k, v)
			}
			r.Header.Del(header)
			w := httptest.NewRecorder()
			f.p.ServeHTTP(w, r)
			if w.Code != 403 || f.stsCalls != 0 || f.originCalls != 0 {
				t.Fatal("missing metadata accepted")
			}
		})
	}
	f := setup(t)
	if f.request("Action=DescribeInstances&Padding="+strings.Repeat("x", 1<<20)).Code != 400 || f.stsCalls != 0 {
		t.Fatal("oversized body accepted")
	}
}
