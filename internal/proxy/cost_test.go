package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

func TestCostExplorerAccountAndGlobalSigning(t *testing.T) {
	f := setup(t)
	f.addAWSAccount(t, "eu-west-1")
	f.mapProject(t, "111111111111", "123456789012", "987654321098")
	if err := f.p.ServiceEndpoint("https://{service}.{region}.example.test"); err != nil {
		t.Fatal(err)
	}
	base, origins := f.p.transport, 0
	f.p.transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == f.stsHost {
			return base.RoundTrip(r)
		}
		origins++
		account, err := resource.Parse[resource.AccountID]("987654321098")
		if err != nil {
			t.Fatal(err)
		}
		verifier := sigv4.NewVerifier(sigv4.Verifier{
			Service: sigv4.Service("ce"),
			Regions: backend.NewStaticRegions(nil, []backend.AWSAccount{
				{ID: account.String(), AllowedRegions: []string{"us-east-1"}},
			}),
			Auth: sigv4.Lookup(func(context.Context, string) (sigv4.Credential, bool) {
				return sigv4.Credential{
					AccessKey: "session-canary-key", Secret: "session-canary-secret",
					SessionToken: "session-token", Account: account,
				}, true
			}),
		})
		if _, err := verifier.Verify(r); err != nil {
			t.Errorf("CE signature: %v", err)
		}
		if r.URL.Host != "ce.us-east-1.example.test" || r.Header.Get("X-Vws-Aws-Account") != "" ||
			r.Header.Get("X-Amz-Target") != "AWSInsightsIndexService.GetCostAndUsage" {
			t.Error("CE endpoint or headers incorrect")
		}
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: http.NoBody, Request: r}, nil
	})
	for range 2 {
		r := serviceRequest("POST", "/", "ce", `{}`)
		r.Header.Set("X-Vws-Account", "111111111111")
		r.Header.Set("X-Vws-Aws-Account", "987654321098")
		r.Header.Set("X-Vws-Target-Region", "eu-west-1")
		r.Header.Set("X-Amz-Target", "AWSInsightsIndexService.GetCostAndUsage")
		w := httptest.NewRecorder()
		f.p.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("CE request: %d %s", w.Code, w.Body)
		}
	}
	if origins != 2 || f.stsCalls != 1 || f.stsForms[0].Get("RoleArn") != "arn:aws:iam::987654321098:role/second" {
		t.Fatal("CE selected the wrong account or bypassed session caching")
	}
	f.p.transport = base
	r := serviceRequest("POST", "/", "ec2", "Action=DescribeInstances")
	r.Header.Set("X-Vws-Aws-Account", "../unmapped")
	w := httptest.NewRecorder()
	f.p.ServeHTTP(w, r)
	if w.Code != 200 || f.stsCalls != 2 ||
		f.stsForms[1].Get("RoleArn") != "arn:aws:iam::123456789012:role/inventory" {
		t.Fatal("CE account header changed EC2 account selection")
	}
}

func TestCostExplorerRefusals(t *testing.T) {
	for _, scenario := range []string{
		"unmapped", "malformed", "missing", "duplicate", "target", "duplicate-target", "method", "path",
	} {
		t.Run(scenario, func(t *testing.T) {
			f := setup(t)
			if err := f.p.ServiceEndpoint("http://127.0.0.1"); err != nil {
				t.Fatal(err)
			}
			r := serviceRequest("POST", "/", "ce", `{}`)
			r.Header.Set("X-Vws-Aws-Account", "123456789012")
			r.Header.Set("X-Amz-Target", "AWSInsightsIndexService.GetCostAndUsage")
			switch scenario {
			case "unmapped":
				r.Header.Set("X-Vws-Aws-Account", "987654321098")
			case "malformed":
				r.Header.Set("X-Vws-Aws-Account", "../secret")
			case "missing":
				r.Header.Del("X-Vws-Aws-Account")
			case "duplicate":
				r.Header.Add("X-Vws-Aws-Account", "123456789012")
			case "target":
				r.Header.Set("X-Amz-Target", "AWSInsightsIndexService.GetCostForecast")
			case "duplicate-target":
				r.Header.Add("X-Amz-Target", "AWSInsightsIndexService.GetCostForecast")
			case "method":
				r.Method = "GET"
			case "path":
				r.URL.Path = "/other"
			}
			w := httptest.NewRecorder()
			f.p.ServeHTTP(w, r)
			if w.Code != 403 || f.stsCalls != 0 || f.originCalls != 0 {
				t.Fatalf("refusal reached upstream: %d %s", w.Code, w.Body)
			}
		})
	}
}
