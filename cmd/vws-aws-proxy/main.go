// Command vws-aws-proxy serves the local EC2 inventory forwarding boundary.
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
	accounts := flag.String("accounts", "", "JSON export of admin AWS account records")
	sts := flag.String("sts-endpoint", "", "STS endpoint URL")
	stsRegion := flag.String("sts-region", "us-east-1",
		"signing region of the STS endpoint (us-east-1 for the global endpoint)")
	origin := flag.String("ec2-endpoint", "", "EC2 URL, optionally containing {region}")
	flag.Parse()
	source, err := proxy.SourceCredential()
	if err != nil {
		return err
	}
	data, err := os.ReadFile(*accounts)
	if err != nil {
		return errors.New("read account registrations")
	}
	var records []store.AWSAccount
	if json.Unmarshal(data, &records) != nil {
		return errors.New("decode account registrations")
	}
	registry := store.New(store.NewMemory())
	for _, a := range records {
		if _, err := registry.AWSAccounts().Create(ctx, a); err != nil {
			return errors.New("load account registrations")
		}
	}
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
