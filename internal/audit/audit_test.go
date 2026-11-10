package audit

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
)

type ctxKey string

func fixedLogger(buf *bytes.Buffer) *Logger {
	l := New(buf)
	l.now = func() time.Time { return time.Date(2026, 11, 10, 9, 30, 0, 0, time.UTC) }
	return l
}

func TestRecordWritesTheFixedSchema(t *testing.T) {
	var buf bytes.Buffer
	err := fixedLogger(&buf).Record(context.Background(), Entry{
		RequestID:    "req-1",
		TraceID:      "4bf92f3577b34da6a3ce929d0e0e4736",
		PrincipalARN: "arn:aws:iam::123456789012:user/ops",
		Account:      "123456789012",
		Region:       "pve-seoul-1",
		Destination:  PVE,
		Service:      "admin",
		Action:       "vws:AdminPutRegion",
		ResourceIDs:  []string{"pve-seoul-1"},
		Result:       Error("conflict"),
		OperationID:  "op-0123456789abcdef0123",
		Latency:      42*time.Millisecond + 900*time.Microsecond,
		SourceIP:     "203.0.113.7",
	})
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"time":"2026-11-10T09:30:00Z","request_id":"req-1","trace_id":"4bf92f3577b34da6a3ce929d0e0e4736",` +
		`"principal_arn":"arn:aws:iam::123456789012:user/ops","account":"123456789012","region":"pve-seoul-1",` +
		`"destination":"pve","service":"admin","action":"vws:AdminPutRegion","resource_ids":["pve-seoul-1"],` +
		`"result":"error:conflict","operation_id":"op-0123456789abcdef0123","latency_ms":42,"source_ip":"203.0.113.7"}` + "\n"
	if got := buf.String(); got != want {
		t.Fatalf("audit line\n got: %s\nwant: %s", got, want)
	}
}

func TestEmptyEntryKeepsEveryField(t *testing.T) {
	var buf bytes.Buffer
	if err := fixedLogger(&buf).Record(context.Background(), Entry{Result: Denied}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"resource_ids":[]`) {
		t.Fatalf("resource_ids must be an empty array: %s", buf.String())
	}
}

func TestContextValuesNeverReachTheLine(t *testing.T) {
	canaries := []string{"canary-secret-key", "canary-bearer-token", `canary-body-{"SecretAccessKey":"x"}`}
	ctx := context.Background()
	for i, c := range canaries {
		ctx = context.WithValue(ctx, ctxKey(string(rune('a'+i))), c)
	}
	var buf bytes.Buffer
	if err := fixedLogger(&buf).Record(ctx, Entry{Action: "vws:AdminPutAWSAccount", Result: Accepted}); err != nil {
		t.Fatal(err)
	}
	for _, c := range canaries {
		if strings.Contains(buf.String(), c) {
			t.Fatalf("audit line carries %q: %s", c, buf.String())
		}
	}
}

func TestRecordLeavesTheAppLoggerAlone(t *testing.T) {
	var app bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&app, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	var buf bytes.Buffer
	e := Entry{Account: "123456789012", Result: Accepted}
	if err := fixedLogger(&buf).Record(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	if app.Len() != 0 {
		t.Fatalf("app logger received the audit line: %s", app.String())
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestRecordReturnsAWriteFailure(t *testing.T) {
	if err := New(failingWriter{}).Record(context.Background(), Entry{Result: Accepted}); err == nil {
		t.Fatal("a lost audit line must be an error")
	}
}
