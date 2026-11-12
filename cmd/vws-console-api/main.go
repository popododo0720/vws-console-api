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

	"github.com/popododo0720/vws-lib/obs"

	adminsecret "github.com/popododo0720/vws-console-api/internal/admin/secret"
	"github.com/popododo0720/vws-console-api/internal/admin/store"
	"github.com/popododo0720/vws-console-api/internal/admin/store/etcdstore"
	"github.com/popododo0720/vws-console-api/internal/audit"
	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/awssdk"
	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/backend/grpcclient"
	"github.com/popododo0720/vws-console-api/internal/backend/grpcclient/iamclient"
	"github.com/popododo0720/vws-console-api/internal/backend/launch"
	"github.com/popododo0720/vws-console-api/internal/backend/launch/kubestore"
	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/globalconfig"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/server"
	"github.com/popododo0720/vws-console-api/internal/service"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
	"github.com/popododo0720/vws-console-api/internal/surface/console"
	"github.com/popododo0720/vws-console-api/internal/surface/ec2query"
	"github.com/popododo0720/vws-console-api/internal/surface/iamquery"
	"github.com/popododo0720/vws-console-api/internal/surface/s3rest"
	"github.com/popododo0720/vws-console-api/internal/throttle"
)

func stopSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM}
}

func main() {
	if err := serve(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "vws-console-api: %v\n", err)
		os.Exit(1)
	}
}

// serve sets up observability once, then runs the process. main defers the
// shutdown through this function so os.Exit does not skip it.
func serve(ctx context.Context, args []string) (err error) {
	shutdown, err := obs.Setup(ctx, obs.ForService(service.Name))
	if err != nil {
		return fmt.Errorf("observability: %w", err)
	}
	defer func() {
		if serr := shutdown(context.WithoutCancel(ctx)); serr != nil {
			err = errors.Join(err, fmt.Errorf("observability shutdown: %w", serr))
		}
	}()
	return run(ctx, args)
}

func run(ctx context.Context, args []string) (err error) {
	fs := flag.NewFlagSet("vws-console-api", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	backendKind := fs.String("backend", "fake", "fake or grpc")
	auditLog := fs.String("audit-log", "", "append-only audit stream path; empty uses stderr")
	awsProxySocket := fs.String("aws-proxy-socket", "/run/vws/aws-proxy.sock", "AWS connection test proxy unix socket")
	globalConfig := fs.String("global-config", "", "global.yaml bootstrap path for the admin registry; "+
		"empty uses memory with -backend=fake")
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
	launchNamespace := fs.String("launch-namespace", "", "Kubernetes namespace that holds the RunInstances launch "+
		"records as ConfigMaps, with -backend=grpc; empty records no launches")
	kubeconfig := fs.String("kubeconfig", "", "kubeconfig path for -launch-namespace; "+
		"empty uses $KUBECONFIG, then the default path, then the in-cluster service account")
	iamMode := fs.String("iam", "static", "static: only the -access-key root key, no IAM/STS management; "+
		"fake: in-memory IAM users, groups, roles, policies and STS sessions, lost on restart; "+
		"grpc: vws-iam at -iam-endpoint authenticates keys, authorizes requests and serves console sign-in and STS AssumeRole")
	iamEndpoint := fs.String("iam-endpoint", "", "vws-iam gRPC address for -iam=grpc, such as vws-iam.vws-system:9095")
	iamTLS := iamclient.TLSFiles{}
	fs.StringVar(&iamTLS.CAFile, "iam-tls-ca-file", "", "PEM CA bundle that verifies the vws-iam server certificate; "+
		"setting it turns on TLS to vws-iam (empty: plaintext)")
	fs.StringVar(&iamTLS.CertFile, "iam-tls-cert-file", "", "PEM client certificate for mutual TLS to vws-iam; "+
		"needs -iam-tls-key-file and -iam-tls-ca-file")
	fs.StringVar(&iamTLS.KeyFile, "iam-tls-key-file", "", "PEM client key for mutual TLS to vws-iam; "+
		"needs -iam-tls-cert-file and -iam-tls-ca-file")
	fs.StringVar(&iamTLS.ServerName, "iam-tls-server-name", "", "name checked against the vws-iam server certificate "+
		"(empty: the -iam-endpoint host)")
	iamAddr := fs.String("iam-addr", "127.0.0.1:8084", "IAM and STS Query listen address")
	consoleOrigins := fs.String("console-origins", "", "comma-separated browser origins allowed to sign in and send cookie writes besides the console's own host, such as https://console.vws.example")
	trustedProxies := fs.String("trusted-proxies", "", "comma-separated CIDRs of L7 proxies in front of the console whose X-Forwarded-For is trusted for the sign-in client address; empty uses the TCP peer")
	rootPasswordFile := fs.String("root-password-file", "",
		"file holding the account root's console password with -iam fake (mount it from a Secret); "+
			"empty disables fake root sign-in; ignored with a warning in static and grpc modes")
	limits := console.DefaultLoginLimits()
	fs.IntVar(&limits.IPBurst, "login-ip-burst", limits.IPBurst,
		"console sign-in attempts one client address may make at once (1 to 10000)")
	fs.DurationVar(&limits.IPRefill, "login-ip-refill", limits.IPRefill,
		"time for one client address to earn one more sign-in attempt (100ms to 24h)")
	fs.IntVar(&limits.UserBurst, "login-user-burst", limits.UserBurst,
		"failed console sign-ins one account user name may take at once, from every address together (1 to 10000)")
	fs.DurationVar(&limits.UserRefill, "login-user-refill", limits.UserRefill,
		"time for one account user name to earn one more failed sign-in (100ms to 24h)")
	fs.IntVar(&limits.MaxKeys, "login-max-keys", limits.MaxKeys,
		"addresses and user names each sign-in limit table holds before it evicts (100 to 1000000)")
	requestLimits := throttle.DefaultLimits()
	for _, c := range []struct {
		name string
		rate *throttle.Rate
	}{
		{"describe", &requestLimits.Describe}, {"mutate", &requestLimits.Mutate}, {"launch", &requestLimits.Launch},
	} {
		fs.IntVar(&c.rate.Burst, "ec2-"+c.name+"-burst", c.rate.Burst,
			"EC2 "+c.name+" requests one account may make at once per action (1 to 100000); see docs/rules.md")
		fs.Float64Var(&c.rate.PerSecond, "ec2-"+c.name+"-rate", c.rate.PerSecond,
			"EC2 "+c.name+" requests one account earns back per action each second (0.01 to 100000)")
	}
	fs.IntVar(&requestLimits.MaxKeys, "ec2-limit-max-keys", requestLimits.MaxKeys,
		"(account, action) buckets the EC2 request limit holds before it evicts (100 to 10000000)")
	launchLimits := throttle.DefaultLaunchLimits()
	fs.IntVar(&launchLimits.PerAccount, "launch-inflight-per-account", launchLimits.PerAccount,
		"instances one account may have in flight in RunInstances, per process (10 to 100000, at most the global cap)")
	fs.IntVar(&launchLimits.Global, "launch-inflight-global", launchLimits.Global,
		"instances in flight in RunInstances across all accounts, per process (10 to 100000)")
	fs.IntVar(&launchLimits.Queue, "launch-queue", launchLimits.Queue,
		"RunInstances calls that may wait for room at once, all accounts together; past it a launch is refused (0 to 100000)")
	fs.DurationVar(&launchLimits.Wait, "launch-queue-wait", launchLimits.Wait,
		"longest a RunInstances call waits for room before RequestLimitExceeded (0 to 30s)")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("flags: %w", err)
	}

	logger := slog.Default()
	creds, err := resolveCredentials(ctx, fs, osCredentialEnv(), logger, consoleToken, accessKey, secret)
	if err != nil {
		return err
	}
	if *backendKind == "grpc" {
		if err := requireExplicit(creds); err != nil {
			return err
		}
	}

	if err := limits.Validate(); err != nil {
		return fmt.Errorf("-login-*: %w", err)
	}
	if err := requestLimits.Validate(); err != nil {
		return fmt.Errorf("-ec2-*: %w", err)
	}
	requests := throttle.New(requestLimits, nil)
	if err := launchLimits.Validate(); err != nil {
		return fmt.Errorf("-launch-*: %w", err)
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
	// sweep undoes the launches a dead request left behind; nil without a launch store.
	var sweep func(context.Context)
	switch *backendKind {
	case "fake":
		if *launchNamespace != "" {
			return errors.New("-launch-namespace needs -backend=grpc")
		}
		direct, parseErr := resource.Parse[resource.SubnetID]("subnet-direct-prod")
		if parseErr != nil {
			return parseErr
		}
		set = fake.New(fake.Options{Direct: []fake.DirectNetwork{{ID: direct, Cidr: "192.168.200.0/24"}}}).Set()
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
		if *launchNamespace == "" {
			logger.WarnContext(ctx, "no -launch-namespace: RunInstances steps are not recorded")
		} else {
			store, openErr := kubestore.Open(*kubeconfig, *launchNamespace)
			if openErr != nil {
				return fmt.Errorf("-launch-namespace: %w", openErr)
			}
			client.SetLaunches(launch.NewTracker(store, nil))
			sweep = client.SweepLaunches
		}
		set = client.Set()
	default:
		return fmt.Errorf("unknown -backend %q", *backendKind)
	}

	registry, adminKey, closeRegistry, err := openRegistry(ctx, *globalConfig, *backendKind)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, closeRegistry()) }()
	health, err := regionHealth(*globalConfig)
	if err != nil {
		return err
	}
	registration, err := regionRegistration(*globalConfig)
	if err != nil {
		return err
	}
	pool, err := regionPool(*globalConfig)
	if err != nil {
		return err
	}
	var regions backend.RegionCatalog = backend.DefaultRegions()
	if *backendKind != "fake" {
		regions = registry.Catalog()
	}
	svc := cloud.New(cloud.Config{
		Backends: set, Regions: regions, Audit: logger, Launches: throttle.NewLaunches(launchLimits),
	})
	// The static key remains the account root for SigV4. With -iam=grpc,
	// vws-iam owns console passwords and sessions for every identity.
	root := iam.NewStatic(*accessKey, *secret, account)
	root.SetLogger(logger)
	if *rootPasswordFile != "" && *iamMode != "grpc" {
		if err := setRootPassword(ctx, root, *rootPasswordFile); err != nil {
			return err
		}
	}
	var auth iam.Client = root
	var admin iam.Directory
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
		dialOpts, tlsErr := iamDialOptions(ctx, logger, iamTLS)
		if tlsErr != nil {
			return tlsErr
		}
		remote, dialErr := iamclient.Dial(*iamEndpoint, dialOpts...)
		if dialErr != nil {
			return dialErr
		}
		defer func() { err = errors.Join(err, remote.Close()) }()
		remote.SetLogger(logger)
		auth, admin = iam.WithRootKey(root, remote), iamclient.STSAdmin{Client: remote}
	default:
		return fmt.Errorf("unknown -iam %q", *iamMode)
	}
	warnSignIn(ctx, logger, *iamMode, *rootPasswordFile)
	authn := iam.Authenticator(auth)
	verifier := func(s sigv4.Service) *sigv4.Verifier {
		return sigv4.NewVerifier(sigv4.Verifier{Service: s, Regions: regions, Auth: authn})
	}
	ec2, s3 := verifier(sigv4.ServiceEC2), verifier(sigv4.ServiceS3)

	ctx, stop := signal.NotifyContext(ctx, stopSignals()...)
	defer stop()
	if sweep != nil {
		go sweep(ctx)
	}
	auditOut := os.Stderr
	if *auditLog != "" {
		auditOut, err = os.OpenFile(*auditLog, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
		if err != nil {
			return fmt.Errorf("open -audit-log: %w", err)
		}
		defer func() { err = errors.Join(err, auditOut.Close()) }()
	}
	connection, err := awssdk.NewConnectionClient(*awsProxySocket)
	if err != nil {
		return err
	}
	defer connection.Close()
	return server.Serve(ctx, server.Options{Logger: logger, OpsAddr: *opsAddr, Surfaces: []server.Surface{
		{Name: "console", Addr: *consoleAddr, Handler: console.New(console.Config{
			Service:        svc,
			Registry:       registry,
			AdminKey:       adminKey,
			Audit:          audit.New(auditOut),
			RegionStatus:   health,
			RegionPool:     pool,
			Auth:           console.BearerTokens{*consoleToken: caller},
			IAM:            auth,
			Logger:         logger,
			Origins:        splitList(*consoleOrigins),
			TrustedProxies: trusted,
			LoginDisabled:  !signInEnabled(*iamMode),
			LoginLimits:    limits,
			Requests:       requests,

			RegionRegistration: registration,
			RegionConnection:   testRegionConnection,
			AccountConnection:  connection.TestConnection,
		})},
		{Name: "ec2", Addr: *ec2Addr, Handler: ec2query.New(ec2query.Config{
			Service: svc, Verifier: ec2, Authorizer: auth, Requests: requests,
		})},
		{Name: "s3", Addr: *s3Addr, Handler: s3rest.New(s3rest.Config{Service: svc, Verifier: s3, Authorizer: auth})},
		{Name: "iam", Addr: *iamAddr, Handler: iamquery.New(iamquery.Config{
			Admin: admin, Authorizer: auth, IAM: verifier(sigv4.ServiceIAM), STS: verifier(sigv4.ServiceSTS),
		})},
	}})
}

func openRegistry(
	ctx context.Context, path, backendKind string,
) (*store.Registry, *adminsecret.Key, func() error, error) {
	if path == "" {
		if backendKind != "fake" {
			return nil, nil, nil, errors.New("-global-config is required for the admin registry with -backend=grpc")
		}
		return store.New(store.NewMemory()), nil, func() error { return nil }, nil
	}
	data, err := os.ReadFile(path) //nolint:gosec // operator-selected bootstrap file.
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read -global-config: %w", err)
	}
	cfg, err := globalconfig.Parse(data)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse -global-config: %w", err)
	}
	key, err := adminsecret.LoadFile(cfg.Credentials.KEKFile)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("load admin KEK: %w", err)
	}
	registry, closeRegistry, err := etcdstore.Open(ctx, cfg.IAM)
	return registry, key, closeRegistry, err
}

// iamDialOptions turns the -iam-tls-* flags into Dial options. Without them
// the connection is plaintext and a warning says so.
func iamDialOptions(
	ctx context.Context, logger *slog.Logger, files iamclient.TLSFiles,
) ([]iamclient.DialOption, error) {
	if !files.Enabled() {
		logger.WarnContext(ctx, "vws-iam connection is plaintext: set -iam-tls-ca-file to turn on TLS")
		return nil, nil
	}
	cfg, err := files.Config()
	if err != nil {
		return nil, err
	}
	logger.InfoContext(ctx, "vws-iam connection uses TLS", slog.Bool("mutual", files.CertFile != ""))
	return []iamclient.DialOption{iamclient.WithTLS(cfg)}, nil
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

// warnSignIn logs disabled sign-in and ignored local password settings.
func warnSignIn(ctx context.Context, logger *slog.Logger, iamMode, rootPasswordFile string) {
	if iamMode == "grpc" && rootPasswordFile != "" {
		logger.WarnContext(ctx, "-root-password-file has no effect with -iam grpc: vws-iam owns console sign-in",
			slog.String("iam", iamMode))
	}
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
