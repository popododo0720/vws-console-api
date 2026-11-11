// Command vws-region serves the read-only Proxmox region API.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/popododo0720/vws-lib/obs"

	"github.com/popododo0720/vws-console-api/internal/backend/proxmox"
	"github.com/popododo0720/vws-console-api/internal/server"
	"github.com/popododo0720/vws-console-api/internal/surface/regionapi"
)

func main() {
	if err := serve(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "vws-region: %v\n", err)
		os.Exit(1)
	}
}

func serve(ctx context.Context, args []string) (err error) {
	shutdown, err := obs.Setup(ctx, obs.ForService("vws-region"))
	if err != nil {
		return fmt.Errorf("observability: %w", err)
	}
	defer func() { err = errors.Join(err, shutdown(context.WithoutCancel(ctx))) }()
	return run(ctx, args)
}

func run(ctx context.Context, args []string) (err error) {
	fs := flag.NewFlagSet("vws-region", flag.ContinueOnError)
	// Flag parsing must not echo an unknown token flag's value.
	fs.SetOutput(io.Discard)
	config := fs.String("config", "/etc/vws/region.yaml", "node-local configuration path")
	kind := fs.String("backend", "proxmox", "proxmox")
	registration := fs.String("registration-file", "/etc/pve/priv/vws/registration.json", "private registration snapshot")
	endpoint := fs.String("pve-endpoint", "https://127.0.0.1:8006", "local pveproxy HTTPS origin")
	pveCA := fs.String("pve-ca-file", "/etc/pve/pve-root-ca.pem", "node CA bundle")
	certFile := fs.String("tls-cert-file", "/etc/vws/region.crt", "region server certificate")
	keyFile := fs.String("tls-key-file", "/etc/vws/region.key", "region server private key")
	caFile := fs.String("tls-ca-file", "/etc/vws/global-ca.pem", "CA for global client certificates")
	addr := fs.String("region-addr", ":8443", "mTLS region API address")
	opsAddr := fs.String("ops-addr", ":8083", "health and metrics address")
	if err := fs.Parse(args); err != nil {
		return errors.New("invalid flags; PVE token flags are forbidden")
	}
	if fs.NArg() != 0 || *kind != "proxmox" {
		return errors.New("expected -backend proxmox and no positional arguments")
	}
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if strings.Contains(name, "TOKEN") && (strings.HasPrefix(name, "PVE_") ||
			strings.HasPrefix(name, "PROXMOX_") || strings.HasPrefix(name, "VWS_")) {
			return errors.New("PVE token environment variables are forbidden; use registration")
		}
	}
	u, err := url.Parse(*endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("pve-endpoint requires an HTTPS origin without credentials")
	}
	pool, err := loadCA(*pveCA)
	if err != nil {
		return err
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}}
	defer transport.CloseIdleConnections()
	conn, err := proxmox.Open(*config, *registration, *endpoint, &http.Client{
		Transport: transport, Timeout: 10 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	})
	if err != nil {
		return err
	}
	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		return fmt.Errorf("region certificate: %w", err)
	}
	ca, err := loadCA(*caFile)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var initialized atomic.Bool
	probe := &readiness{check: func(ctx context.Context) error {
		_, err := conn.Check(ctx)
		return err
	}, now: time.Now, ttl: readyTTL}
	opsDone := make(chan error, 1)
	go func() {
		opsDone <- server.Serve(ctx, server.Options{
			Logger: slog.Default(), OpsAddr: *opsAddr,
			Ready: func(ctx context.Context) error {
				if !initialized.Load() {
					return errors.New("startup checks incomplete")
				}
				return probe.Ready(ctx)
			},
		})
		cancel()
	}()
	defer func() {
		initialized.Store(false)
		cancel()
		err = errors.Join(err, <-opsDone)
	}()
	b, err := conn.Check(ctx)
	if err != nil {
		return err
	}
	identity := conn.Identity()
	h, err := regionapi.New(regionapi.Config{
		Backend: b.Set(), Capabilities: b, Region: identity.Region.Name,
		Version: regionapi.Version{ReleaseLine: "1.0", ClusterName: identity.ClusterName},
	})
	if err != nil {
		return err
	}
	srv := regionapi.NewServer(*addr, h, cert, ca)
	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", *addr)
	if err != nil {
		return fmt.Errorf("region listen: %w", err)
	}
	done := make(chan error, 1)
	go func() {
		done <- srv.Serve(ln)
		cancel()
	}()
	initialized.Store(true)
	<-ctx.Done()
	initialized.Store(false)
	shutCtx, shutCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer shutCancel()
	err = errors.Join(err, srv.Shutdown(shutCtx))
	if serveErr := <-done; !errors.Is(serveErr, http.ErrServerClosed) {
		err = errors.Join(err, serveErr)
	}
	return err
}

// readyTTL bounds how often unauthenticated /readyz probes reach pveproxy.
const readyTTL = 2 * time.Second

// readiness reuses one PVE check for ttl; concurrent probes wait for the
// check in flight instead of starting their own.
type readiness struct {
	check func(context.Context) error
	now   func() time.Time
	ttl   time.Duration

	mu  sync.Mutex
	at  time.Time
	err error
}

func (r *readiness) Ready(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.at.IsZero() && r.now().Sub(r.at) < r.ttl {
		return r.err
	}
	err := r.check(ctx)
	if ctx.Err() != nil {
		// A probe that gave up says nothing about PVE.
		return err
	}
	r.at, r.err = r.now(), err
	return err
}

func loadCA(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CA bundle: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, errors.New("CA bundle contains no certificates")
	}
	return pool, nil
}
