// Command vws-aws-proxy serves local EC2 inventory and AWS connection tests.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/popododo0720/vws-lib/obs"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/popododo0720/vws-console-api/internal/admin/store"
	"github.com/popododo0720/vws-console-api/internal/admin/store/etcdstore"
	"github.com/popododo0720/vws-console-api/internal/globalconfig"
	"github.com/popododo0720/vws-console-api/internal/proxy"
)

func main() {
	if err := run(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "vws-aws-proxy: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) (err error) {
	socket := flag.String("socket", "/run/vws/aws-proxy.sock", "unix socket in a private directory")
	global := flag.String("global-config", "", "global.yaml bootstrap for the live admin registry")
	accounts := flag.String("accounts", "", "JSON export of admin AWS account records")
	projects := flag.String("projects", "", "JSON export of admin project mappings")
	sts := flag.String("sts-endpoint", "", "STS endpoint URL")
	stsRegion := flag.String("sts-region", "us-east-1",
		"signing region of the STS endpoint (us-east-1 for the global endpoint)")
	origin := flag.String("ec2-endpoint", "", "EC2 URL, optionally containing {region}")
	flag.Parse()
	source, err := proxy.SourceCredential()
	if err != nil {
		return err
	}
	registry, closeRegistry, err := openRegistry(ctx, *global, *accounts, *projects)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, closeRegistry()) }()
	p, err := proxy.New(proxy.RegistryAccounts{
		Registry:            registry,
		CredentialDirectory: os.Getenv("CREDENTIALS_DIRECTORY"),
	}, source, *sts, *stsRegion, *origin)
	if err != nil {
		return err
	}
	shutdown, err := obs.Setup(ctx, obs.ForService("vws-aws-proxy"))
	if err != nil {
		return fmt.Errorf("observability: %w", err)
	}
	defer func() { err = errors.Join(err, shutdown(context.WithoutCancel(ctx))) }()
	oldMask := syscall.Umask(0o077)
	l, err := (&net.ListenConfig{}).Listen(ctx, "unix", *socket)
	syscall.Umask(oldMask)
	if err != nil {
		return fmt.Errorf("listen unix: %w", err)
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	srv := &http.Server{
		Handler:           otelhttp.NewHandler(p, "aws-proxy"),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 35 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384,
	}
	stopped := make(chan error, 1)
	go func() {
		<-ctx.Done()
		closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if shutdownErr := srv.Shutdown(closeCtx); shutdownErr != nil {
			stopped <- errors.Join(shutdownErr, srv.Close())
			return
		}
		stopped <- nil
	}()
	if err := srv.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve: %w", err)
	}
	if err := <-stopped; err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	return nil
}

func openRegistry(ctx context.Context, global, accounts, projects string) (*store.Registry, func() error, error) {
	if global != "" {
		if accounts != "" || projects != "" {
			return nil, nil, errors.New("global config conflicts with registration snapshots")
		}
		data, err := os.ReadFile(global) //nolint:gosec // operator-selected bootstrap file.
		if err != nil {
			return nil, nil, fmt.Errorf("read global config: %w", err)
		}
		cfg, err := globalconfig.Parse(data)
		if err != nil {
			return nil, nil, fmt.Errorf("parse global config: %w", err)
		}
		return etcdstore.Open(ctx, cfg.IAM)
	}
	data, err := os.ReadFile(accounts) //nolint:gosec // operator-selected snapshot file.
	if err != nil {
		return nil, nil, errors.New("read account registrations")
	}
	var records []store.AWSAccount
	if json.Unmarshal(data, &records) != nil {
		return nil, nil, errors.New("decode account registrations")
	}
	registry := store.New(store.NewMemory())
	for _, a := range records {
		if _, err := registry.AWSAccounts().Create(ctx, a); err != nil {
			return nil, nil, errors.New("load account registrations")
		}
	}
	data, err = os.ReadFile(projects) //nolint:gosec // operator-selected snapshot file.
	if err != nil {
		return nil, nil, errors.New("read project mappings")
	}
	var mappings []store.Project
	if json.Unmarshal(data, &mappings) != nil {
		return nil, nil, errors.New("decode project mappings")
	}
	for _, mapping := range mappings {
		if _, err := registry.Projects().Put(ctx, mapping); err != nil {
			return nil, nil, errors.New("load project mappings")
		}
	}
	return registry, func() error { return nil }, nil
}
