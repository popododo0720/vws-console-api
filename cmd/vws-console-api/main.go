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
	"strings"
	"syscall"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/backend/grpcclient"
	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/server"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
	"github.com/popododo0720/vws-console-api/internal/surface/console"
	"github.com/popododo0720/vws-console-api/internal/surface/ec2query"
	"github.com/popododo0720/vws-console-api/internal/surface/iamquery"
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
	opsAddr := fs.String("ops-addr", "127.0.0.1:8083", "address for /healthz, /readyz, and /metrics; empty disables it")
	accountRaw := fs.String("account", "123456789012", "account id for the static credential")
	consoleToken := fs.String("console-token", "dev-token", "bearer token accepted on the console")
	accessKey := fs.String("access-key", "AKIDEXAMPLE", "access key accepted by the signature check")
	secret := fs.String("secret", "secret", "secret for -access-key")
	computeAddr := fs.String("compute-addr", "127.0.0.1:19001", "compute gRPC address")
	storageAddr := fs.String("storage-addr", "127.0.0.1:19002", "storage gRPC address")
	networkAddr := fs.String("network-addr", "127.0.0.1:19003", "network gRPC address")
	iamMode := fs.String("iam", "static", "static: only the -access-key root key, no IAM/STS management; "+
		"fake: in-memory IAM users, groups, roles, policies and STS sessions, lost on restart, until the vws-iam client lands (vws-proto#24)")
	iamAddr := fs.String("iam-addr", "127.0.0.1:8084", "IAM and STS Query listen address")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("flags: %w", err)
	}

	if *backendKind == "grpc" {
		if err := requireExplicit(fs, "console-token", "access-key", "secret"); err != nil {
			return err
		}
	}

	account, err := resource.Parse[resource.AccountID](*accountRaw)
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	caller := resource.Caller{Account: account, Subject: *accessKey, Principal: iam.RootARN(account), Root: true}

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
	// The static key is the account root. Once the vws/iam/v1 client exists
	// (vws-proto#24) it goes behind iam.WithRoot.
	root := iam.NewStatic(*accessKey, *secret, account)
	var auth iam.Client = root
	var admin iam.Admin
	switch *iamMode {
	case "static":
	case "fake":
		fakeIAM := iam.NewFake()
		auth, admin = iam.WithRoot(root, fakeIAM), fakeIAM
		logger.WarnContext(ctx, "in-memory IAM: users, keys and roles are lost on restart", slog.String("iam", *iamMode))
	default:
		return fmt.Errorf("unknown -iam %q", *iamMode)
	}
	authn := iam.Authenticator(auth)
	verifier := func(s sigv4.Service) *sigv4.Verifier {
		return sigv4.NewVerifier(sigv4.Verifier{Service: s, Region: resource.RegionName, Auth: authn})
	}
	ec2, s3 := verifier(sigv4.ServiceEC2), verifier(sigv4.ServiceS3)

	ctx, stop := signal.NotifyContext(ctx, stopSignals()...)
	defer stop()
	return server.Serve(ctx, server.Options{Logger: logger, OpsAddr: *opsAddr, Surfaces: []server.Surface{
		{Name: "console", Addr: *consoleAddr, Handler: console.New(console.Config{
			Service: svc,
			Auth:    console.BearerTokens{*consoleToken: caller},
		})},
		{Name: "ec2", Addr: *ec2Addr, Handler: ec2query.New(ec2query.Config{Service: svc, Verifier: ec2, Authorizer: auth})},
		{Name: "s3", Addr: *s3Addr, Handler: s3rest.New(s3rest.Config{Service: svc, Verifier: s3, Authorizer: auth})},
		{Name: "iam", Addr: *iamAddr, Handler: iamquery.New(iamquery.Config{
			Admin: admin, Authorizer: auth, IAM: verifier(sigv4.ServiceIAM), STS: verifier(sigv4.ServiceSTS),
		})},
	}})
}

// requireExplicit rejects a run that would fall back to a built-in development
// credential. The defaults (dev-token, AKIDEXAMPLE, secret) are public, so
// against real backends each credential flag must be given on the command line.
func requireExplicit(fs *flag.FlagSet, names ...string) error {
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	var missing []string
	for _, name := range names {
		if !set[name] {
			missing = append(missing, "-"+name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("-backend=grpc needs explicit %s; the defaults are public development credentials", strings.Join(missing, ", "))
	}
	return nil
}
