package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/popododo0720/vws-lib/obs"

	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/service"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

// ec2RequestID matches the request id of an EC2 answer: requestId on a
// success, RequestID on an error.
var ec2RequestID = regexp.MustCompile(`<(?:requestId|RequestID)>([^<]*)</(?:requestId|RequestID)>`)

// TestEC2RequestIDMatchesTheLog sends EC2 Query requests to the process and
// checks that the RequestId in each answer body is the request_id of its
// "request" log line (issue #33). It covers a success and an error.
func TestEC2RequestIDMatchesTheLog(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("VWS_HEALTH_ADDR", "")
	logs := &syncBuffer{}
	previous := slog.Default()
	shutdown, err := obs.Setup(t.Context(), obs.ForService(service.Name),
		obs.WithOverride(func(c *obs.Config) { c.LogOutput = logs }))
	if err != nil {
		t.Fatalf("obs.Setup: %v", err)
	}
	t.Cleanup(func() {
		if err := shutdown(context.WithoutCancel(t.Context())); err != nil {
			t.Errorf("obs shutdown: %v", err)
		}
		slog.SetDefault(previous)
	})

	p := startFakeProcess(t)
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	cred := sigv4.Credential{AccessKey: "AKIDEXAMPLE", Secret: "secret", Account: account}
	tests := []struct {
		name string
		form url.Values
		code int
	}{
		{
			name: "success",
			form: url.Values{"Action": {"DescribeKeyPairs"}, "Version": {"2016-11-15"}},
			code: http.StatusOK,
		},
		{
			name: "error",
			form: url.Values{"Action": {"DescribeInstances"}, "Version": {"2016-11-15"}, "InstanceId.1": {"i-bad"}},
			code: http.StatusBadRequest,
		},
	}
	seen := map[string]bool{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, body := signedStatus(t, cred, sigv4.ServiceEC2, time.Now().UTC(), http.MethodPost,
				"http://"+p.ec2+"/", tt.form.Encode(), "application/x-www-form-urlencoded")
			if code != tt.code {
				t.Fatalf("status %d, want %d: %s", code, tt.code, body)
			}
			m := ec2RequestID.FindStringSubmatch(body)
			if m == nil || m[1] == "" {
				t.Fatalf("no RequestId in the answer: %s", body)
			}
			id := m[1]
			if seen[id] {
				t.Fatalf("request id %q answered twice", id)
			}
			seen[id] = true
			if !ec2LogRequestIDs(t, logs.String())[id] {
				t.Fatalf("RequestId %q is not the request_id of any ec2 request log line:\n%s", id, logs.String())
			}
		})
	}
}

// ec2LogRequestIDs returns the request_id of every "request" log line of the
// ec2 surface.
func ec2LogRequestIDs(t *testing.T, logs string) map[string]bool {
	t.Helper()
	ids := map[string]bool{}
	for _, line := range strings.Split(logs, "\n") {
		var entry map[string]any
		if json.Unmarshal([]byte(line), &entry) != nil || entry["msg"] != "request" || entry["surface"] != "ec2" {
			continue
		}
		if id, ok := entry["request_id"].(string); ok {
			ids[id] = true
		}
	}
	return ids
}

// syncBuffer is a bytes.Buffer the server goroutines and the test may use at
// once.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
