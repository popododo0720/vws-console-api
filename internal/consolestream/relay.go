// Package consolestream relays framed console bytes without exposing credentials.
package consolestream

import (
	"context"
	"errors"
	"io"
	"log/slog"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// Close releases a console stream without publishing transport error details.
func Close(ctx context.Context, stream resource.ConsoleStream) {
	if err := stream.Close(); err != nil {
		slog.DebugContext(ctx, "console close ended")
	}
}

// Relay copies both directions until either peer ends or the context expires.
func Relay(ctx context.Context, upstream, downstream resource.ConsoleStream) {
	stop := context.AfterFunc(ctx, func() {
		Close(ctx, upstream)
		Close(ctx, downstream)
	})
	defer stop()
	done := make(chan error, 2)
	go func() { done <- copyConsole(upstream, downstream) }()
	go func() { done <- copyConsole(downstream, upstream) }()
	if err := <-done; err != nil {
		slog.DebugContext(ctx, "console stream ended")
	}
	Close(ctx, upstream)
	Close(ctx, downstream)
	if err := <-done; err != nil {
		slog.DebugContext(ctx, "console peer ended")
	}
}

func copyConsole(dst, src resource.ConsoleStream) error {
	for {
		kind, reader, err := src.NextReader()
		if err != nil {
			return err
		}
		writer, err := dst.NextWriter(kind)
		if err != nil {
			return err
		}
		_, err = io.Copy(writer, reader)
		if err = errors.Join(err, writer.Close()); err != nil {
			return err
		}
	}
}
