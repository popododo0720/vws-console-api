// Command vws-console-api serves the console JSON API, an EC2 Query entry
// point, and an S3-style object entry point. It stores nothing.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/backend/grpcclient"
	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/server"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
	"github.com/popododo0720/vws-console-api/internal/surface/console"
	"github.com/popododo0720/vws-console-api/internal/surface/ec2query"
	"github.com/popododo0720/vws-console-api/internal/surface/s3rest"
)

func stopSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM}
}

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "vws-console-api: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) (err error) {
	fs := flag.NewFlagSet("vws-console-api", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	backendKind := fs.String("backend", "fake", "fake or grpc")
	consoleAddr := fs.String("console-addr", "127.0.0.1:8080", "console listen address")
	ec2Addr := fs.String("ec2-addr", "127.0.0.1:8081", "query listen address")
	s3Addr := fs.String("s3-addr", "127.0.0.1:8082", "object listen address")
	accountRaw := fs.String("account", "123456789012", "account id for the static credential")
	consoleToken := fs.String("console-token", "dev-token", "bearer token accepted on the console")
	accessKey := fs.String("access-key", "AKIDEXAMPLE", "access key accepted by the signature check")
	secret := fs.String("secret", "secret", "secret for -access-key")
	computeAddr := fs.String("compute-addr", "127.0.0.1:19001", "compute gRPC address")
	storageAddr := fs.String("storage-addr", "127.0.0.1:19002", "storage gRPC address")
	networkAddr := fs.String("network-addr", "127.0.0.1:19003", "network gRPC address")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("flags: %w", err)
	}

	account, err := resource.Parse[resource.AccountID](*accountRaw)
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	caller := resource.Caller{Account: account, Subject: *accessKey}

	var set backend.Set
	switch *backendKind {
	case "fake":
		set = fake.New(fake.Options{}).Set()
	case "grpc":
		client, dialErr := grpcclient.Dial(ctx, grpcclient.Addrs{
			Compute: *computeAddr,
			Storage: *storageAddr,
			Network: *networkAddr,
		})
		if dialErr != nil {
			return dialErr
		}
		defer func() { err = errors.Join(err, client.Close()) }()
		set = client.Set()
	default:
		return fmt.Errorf("unknown -backend %q", *backendKind)
	}

	svc := cloud.New(cloud.Config{Backends: set, Audit: logger})
	lookup := func(_ context.Context, key string) (sigv4.Credential, bool) {
		if key != *accessKey {
			return sigv4.Credential{}, false
		}
		return sigv4.Credential{AccessKey: *accessKey, Secret: *secret, Account: account}, true
	}
	ec2 := sigv4.NewVerifier(sigv4.Verifier{Service: sigv4.ServiceEC2, Region: resource.RegionName, Lookup: lookup})
	s3 := sigv4.NewVerifier(sigv4.Verifier{Service: sigv4.ServiceS3, Region: resource.RegionName, Lookup: lookup})

	ctx, stop := signal.NotifyContext(ctx, stopSignals()...)
	defer stop()
	return server.Run(ctx, logger,
		server.Surface{Name: "console", Addr: *consoleAddr, Handler: console.New(console.Config{
			Service: svc,
			Auth:    console.BearerTokens{*consoleToken: caller},
		})},
		server.Surface{Name: "ec2", Addr: *ec2Addr, Handler: ec2query.New(ec2query.Config{Service: svc, Verifier: ec2})},
		server.Surface{Name: "s3", Addr: *s3Addr, Handler: s3rest.New(s3rest.Config{Service: svc, Verifier: s3})},
	)
}
