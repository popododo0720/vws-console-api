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
	"github.com/popododo0720/vws-console-api/internal/backend/grpcclient/iamclient"
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
	consoleToken := fs.String("console-token", "dev-token", "deprecated: bearer token accepted on the console; use VWS_CONSOLE_TOKEN or VWS_CONSOLE_TOKEN_FILE")
	accessKey := fs.String("access-key", "AKIDEXAMPLE", "deprecated: access key accepted by the signature check; use VWS_ACCESS_KEY or VWS_ACCESS_KEY_FILE")
	secret := fs.String("secret", "secret", "deprecated: secret for the access key; use VWS_SECRET_KEY or VWS_SECRET_KEY_FILE")
	computeAddr := fs.String("compute-addr", "127.0.0.1:19001", "compute gRPC address")
	storageAddr := fs.String("storage-addr", "127.0.0.1:19002", "storage gRPC address")
	networkAddr := fs.String("network-addr", "127.0.0.1:19003", "network gRPC address")
	iamMode := fs.String("iam", "static", "static: only the -access-key root key, no IAM/STS management; "+
		"fake: in-memory IAM users, groups, roles, policies and STS sessions, lost on restart; "+
		"grpc: vws-iam at -iam-endpoint authenticates keys, authorizes requests and serves console sign-in and STS AssumeRole")
	iamEndpoint := fs.String("iam-endpoint", "", "vws-iam gRPC address for -iam=grpc, such as vws-iam.vws-system:9095")
	iamAddr := fs.String("iam-addr", "127.0.0.1:8084", "IAM and STS Query listen address")
	consoleOrigins := fs.String("console-origins", "", "comma-separated browser origins allowed to sign in and send cookie writes besides the console's own host, such as https://console.vws.example")
	trustedProxies := fs.String("trusted-proxies", "", "comma-separated CIDRs of L7 proxies in front of the console whose X-Forwarded-For is trusted for the sign-in client address; empty uses the TCP peer")
	rootPasswordFile := fs.String("root-password-file", "", "file holding the account root's console password (mount it from a Secret); empty disables root console sign-in; no effect with -iam static, where console sign-in is off")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("flags: %w", err)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	creds, err := resolveCredentials(ctx, fs, osCredentialEnv(), logger, consoleToken, accessKey, secret)
	if err != nil {
		return err
	}
	if *backendKind == "grpc" {
		if err := requireExplicit(creds); err != nil {
			return err
		}
	}

	trusted, err := console.ParseTrustedProxies(*trustedProxies)
	if err != nil {
		return fmt.Errorf("-trusted-proxies: %w", err)
	}
	account, err := resource.Parse[resource.AccountID](*accountRaw)
	if err != nil {
		return err
	}
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
		client.SetLogger(logger)
		set = client.Set()
	default:
		return fmt.Errorf("unknown -backend %q", *backendKind)
	}

	svc := cloud.New(cloud.Config{Backends: set, Audit: logger})
	// The static key is the account root; with -iam=fake or -iam=grpc it
	// sits in front of the IAM client through iam.WithRoot.
	root := iam.NewStatic(*accessKey, *secret, account)
	root.SetLogger(logger)
	if *rootPasswordFile != "" {
		if err := setRootPassword(ctx, root, *rootPasswordFile); err != nil {
			return err
		}
	}
	var auth iam.Client = root
	var admin iam.Admin
	switch *iamMode {
	case "static":
	case "fake":
		fakeIAM := iam.NewFake()
		fakeIAM.SetLogger(logger)
		auth, admin = iam.WithRoot(root, fakeIAM), fakeIAM
		logger.WarnContext(ctx, "in-memory IAM: users, keys and roles are lost on restart", slog.String("iam", *iamMode))
	case "grpc":
		if *iamEndpoint == "" {
			return errors.New("-iam=grpc needs -iam-endpoint")
		}
		remote, dialErr := iamclient.Dial(*iamEndpoint)
		if dialErr != nil {
			return dialErr
		}
		defer func() { err = errors.Join(err, remote.Close()) }()
		auth, admin = iam.WithRoot(root, remote), iamclient.STSAdmin{Client: remote}
	default:
		return fmt.Errorf("unknown -iam %q", *iamMode)
	}
	warnSignIn(ctx, logger, *iamMode, *rootPasswordFile)
	authn := iam.Authenticator(auth)
	verifier := func(s sigv4.Service) *sigv4.Verifier {
		return sigv4.NewVerifier(sigv4.Verifier{Service: s, Region: resource.RegionName, Auth: authn})
	}
	ec2, s3 := verifier(sigv4.ServiceEC2), verifier(sigv4.ServiceS3)

	ctx, stop := signal.NotifyContext(ctx, stopSignals()...)
	defer stop()
	return server.Serve(ctx, server.Options{Logger: logger, OpsAddr: *opsAddr, Surfaces: []server.Surface{
		{Name: "console", Addr: *consoleAddr, Handler: console.New(console.Config{
			Service:        svc,
			Auth:           console.BearerTokens{*consoleToken: caller},
			IAM:            auth,
			Logger:         logger,
			Origins:        splitList(*consoleOrigins),
			TrustedProxies: trusted,
			LoginDisabled:  !signInEnabled(*iamMode),
		})},
		{Name: "ec2", Addr: *ec2Addr, Handler: ec2query.New(ec2query.Config{Service: svc, Verifier: ec2, Authorizer: auth})},
		{Name: "s3", Addr: *s3Addr, Handler: s3rest.New(s3rest.Config{Service: svc, Verifier: s3, Authorizer: auth})},
		{Name: "iam", Addr: *iamAddr, Handler: iamquery.New(iamquery.Config{
			Admin: admin, Authorizer: auth, IAM: verifier(sigv4.ServiceIAM), STS: verifier(sigv4.ServiceSTS),
		})},
	}})
}

// splitList splits a comma-separated flag, dropping empty items.
func splitList(raw string) []string {
	var out []string
	for _, v := range strings.Split(raw, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// setRootPassword reads the root console password from path. One trailing
// newline is dropped, as Secret files and echo leave one.
func setRootPassword(ctx context.Context, root *iam.Static, path string) error {
	raw, err := os.ReadFile(path) //nolint:gosec // an operator-chosen path, read once at start.
	if err != nil {
		return fmt.Errorf("-root-password-file: %w", err)
	}
	pw := strings.TrimSuffix(strings.TrimSuffix(string(raw), "\n"), "\r")
	if err := root.SetPassword(ctx, pw); err != nil {
		return fmt.Errorf("-root-password-file %s: %w", path, err)
	}
	return nil
}

// resolveCredentials resolves the three credentials in place (see credential)
// and returns the ones that were left at their development default.
func resolveCredentials(ctx context.Context, fs *flag.FlagSet, env credentialEnv, logger *slog.Logger, consoleToken, accessKey, secret *string) ([]credential, error) {
	var defaulted []credential
	for _, c := range []struct {
		cred credential
		dst  *string
	}{{credConsoleToken(), consoleToken}, {credAccessKey(), accessKey}, {credSecret(), secret}} {
		v, given, err := resolveCredential(ctx, fs, env, logger, c.cred, *c.dst)
		if err != nil {
			return nil, err
		}
		*c.dst = v
		if !given {
			defaulted = append(defaulted, c.cred)
		}
	}
	return defaulted, nil
}

// requireExplicit rejects a run that would fall back to a built-in development
// credential. The defaults (dev-token, AKIDEXAMPLE, secret) are public, so
// against real backends each credential must be given (env, _FILE or flag).
func requireExplicit(defaulted []credential) error {
	if len(defaulted) == 0 {
		return nil
	}
	var missing []string
	for _, c := range defaulted {
		missing = append(missing, c.env+" (or "+c.env+"_FILE)")
	}
	return fmt.Errorf("-backend=grpc needs %s; the defaults are public development credentials", strings.Join(missing, ", "))
}

// signInEnabled reports whether -iam serves console sign-in. Static has only
// the access key and the bearer console token: login is off even with
// -root-password-file, so the default install never takes a password.
func signInEnabled(iamMode string) bool { return iamMode == "fake" || iamMode == "grpc" }

// warnSignIn logs at start when console sign-in is off.
func warnSignIn(ctx context.Context, logger *slog.Logger, iamMode, rootPasswordFile string) {
	if signInEnabled(iamMode) {
		return
	}
	logger.WarnContext(ctx, "console sign-in disabled: the console accepts only the bearer -console-token; use -iam fake or grpc for sign-in",
		slog.String("iam", iamMode))
	if rootPasswordFile != "" {
		logger.WarnContext(ctx, "-root-password-file has no effect with -iam static: console sign-in is disabled",
			slog.String("iam", iamMode))
	}
}
