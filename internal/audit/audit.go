// Package audit records every change request as one JSON line on a stream of its own.
package audit

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"
)

// Destination is where a change request goes.
type Destination string

// The destinations a change request can go to.
const (
	PVE   Destination = "pve"
	AWS   Destination = "aws"
	IAM   Destination = "iam"
	Admin Destination = "admin"
)

// Result is how a change request ended: Accepted, Denied or Error(code).
type Result string

// The results that carry no error code.
const (
	Accepted Result = "accepted"
	Denied   Result = "denied"
)

// Error is the result of a request that failed with code.
func Error(code string) Result { return Result("error:" + code) }

// Entry is one change request. The logger writes these fields and nothing else.
type Entry struct {
	RequestID    string
	TraceID      string
	PrincipalARN string
	Account      string
	Region       string
	Destination  Destination
	Service      string
	Action       string
	ResourceIDs  []string
	Result       Result
	OperationID  string
	Latency      time.Duration
	SourceIP     string
}

// Logger writes audit lines. It is not the app logger: it never touches slog.Default
// and the app-log rule that a log line carries no account id does not apply to it.
type Logger struct {
	handler slog.Handler
	now     func() time.Time
}

// New returns a Logger that writes one JSON line per Record to w.
func New(w io.Writer) *Logger {
	return &Logger{
		handler: slog.NewJSONHandler(w, &slog.HandlerOptions{ReplaceAttr: dropLevelAndMessage}),
		now:     time.Now,
	}
}

func dropLevelAndMessage(groups []string, a slog.Attr) slog.Attr {
	if len(groups) == 0 && (a.Key == slog.LevelKey || a.Key == slog.MessageKey) {
		return slog.Attr{}
	}
	return a
}

// Record writes e as one line. Only e is read; ctx carries cancellation and nothing else into the line.
func (l *Logger) Record(ctx context.Context, e Entry) error {
	ids := e.ResourceIDs
	if ids == nil {
		ids = []string{}
	}
	r := slog.NewRecord(l.now(), slog.LevelInfo, "", 0)
	r.AddAttrs(
		slog.String("request_id", e.RequestID),
		slog.String("trace_id", e.TraceID),
		slog.String("principal_arn", e.PrincipalARN),
		slog.String("account", e.Account),
		slog.String("region", e.Region),
		slog.String("destination", string(e.Destination)),
		slog.String("service", e.Service),
		slog.String("action", e.Action),
		slog.Any("resource_ids", ids),
		slog.String("result", string(e.Result)),
		slog.String("operation_id", e.OperationID),
		slog.Int64("latency_ms", e.Latency.Milliseconds()),
		slog.String("source_ip", e.SourceIP),
	)
	if err := l.handler.Handle(ctx, r); err != nil {
		return fmt.Errorf("write audit line: %w", err)
	}
	return nil
}
