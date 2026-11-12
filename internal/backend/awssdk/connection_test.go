package awssdk

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestAWSConnectionRejectsProxyAnswers(t *testing.T) {
	valid, _ := json.Marshal(struct {
		Steps []resource.ConnectionStep `json:"steps"`
	}{
		resource.AWSConnectionSteps(true, true),
	})
	for _, body := range []string{
		"<Response/>", `{"steps":[]}`, strings.Repeat("x", 4097),
		strings.Replace(string(valid), `"PASS"`, `"unknown"`, 1),
		strings.Replace(string(valid), "AssumeRole succeeded", "external-canary", 1),
		strings.Replace(string(valid), `"assume_role"`, `"get_caller_identity"`, 1),
		strings.Replace(string(valid), `"PASS"`, `"FAIL"`, 1),
		strings.Replace(string(valid), "AssumeRole succeeded", `bad\u0000text`, 1),
		strings.Replace(string(valid), `"steps":`, `"steps":[],"steps":`, 1),
		strings.Replace(string(valid), `"steps":`, `"Steps":`, 1),
		strings.Replace(string(valid), `"steps":`, `"extra":"canary","steps":`, 1),
		strings.Replace(string(valid), `"result":`, `"result":"FAIL","result":`, 1),
		strings.Replace(string(valid), `"result":`, `"extra":"canary","result":`, 1),
		string(valid) + "{}",
		string(valid), string(valid) + " ", string(valid) + "  ",
		string(valid) + strings.Repeat(" ", 4097-len(valid)),
	} {
		t.Run(fmt.Sprint(len(body)), func(t *testing.T) {
			socket := fixtureSocket(t)
			var calls atomic.Int32
			l, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", socket)
			if err != nil {
				t.Fatal(err)
			}
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				if r.Method != http.MethodPost || r.URL.Path != "/internal/v1/aws-accounts/test" ||
					r.Header.Get("X-Vws-Principal") != "principal" || r.Header.Get("X-Vws-Target-Service") != "sts" {
					t.Error("incorrect private protocol")
				}
				switch body {
				case "<Response/>":
					w.WriteHeader(http.StatusForbidden)
				case string(valid):
					w.WriteHeader(http.StatusInternalServerError)
				case string(valid) + " ":
					w.Header().Set("Location", "/redirect")
					w.WriteHeader(http.StatusTemporaryRedirect)
				case string(valid) + "  ":
					w.Header().Set("Content-Type", "text/plain")
				}
				fmt.Fprint(w, body)
			})
			srv := &http.Server{ReadHeaderTimeout: time.Second, Handler: handler}
			done := make(chan error, 1)
			go func() { done <- srv.Serve(l) }()
			defer func() { srv.Close(); <-done }()
			client, err := NewConnectionClient(socket)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			steps := client.TestConnection(t.Context(), resource.AWSConnectionRequest{
				AccountID: "123456789012", RoleARN: "arn:aws:iam::123456789012:role/inventory", ExternalID: "external-canary",
			}, "principal")
			if !reflect.DeepEqual(steps, unavailableSteps()) || calls.Load() != 1 {
				t.Fatalf("proxy answer escaped: %+v", steps)
			}
		})
	}
}
