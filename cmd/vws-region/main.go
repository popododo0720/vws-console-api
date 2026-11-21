// Command vws-region serves the read-only Proxmox region API.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/popododo0720/vws-lib/obs"
	"github.com/popododo0720/vws-lib/obs/report"

	"github.com/popododo0720/vws-console-api/internal/backend/proxmox"
	"github.com/popododo0720/vws-console-api/internal/resource"
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
	region := fs.String("region", "", "region name this instance serves (required)")
	stateDir := fs.String("state-dir", "", "state directory; default /var/lib/vws-region/<region>")
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
	if *stateDir == "" && *region != "" {
		*stateDir = filepath.Join("/var/lib/vws-region", *region)
	}
	conn, err := proxmox.Open(*config, *region, *stateDir)
	if err != nil {
		return err
	}
	defer conn.Close()
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
	daemonCtx := ctx
	var initialized atomic.Bool
	var state atomic.Pointer[http.Handler]
	var gated atomic.Pointer[proxmox.QuorumGate]
	var gateBackend *proxmox.Backend
	var gateCancel context.CancelFunc
	var gateDone chan struct{}
	probe := &readiness{check: func(ctx context.Context) error {
		b, err := conn.Check(ctx)
		if err != nil {
			if ctx.Err() == nil {
				state.Store(nil)
			}
			return err
		}
		if b == gateBackend && state.Load() != nil {
			return nil
		}
		identity := proxmox.Identity(b)
		if b != gateBackend {
			if gateCancel != nil {
				gateCancel()
				<-gateDone
			}
			gate := proxmox.NewQuorumGate(b)
			gateCtx, stopGate := context.WithCancel(daemonCtx)
			gateCancel, gateDone, gateBackend = stopGate, make(chan struct{}), b
			gated.Store(gate)
			done := gateDone
			go func() {
				defer close(done)
				finalized := make(chan struct{})
				go func() {
					defer close(finalized)
					ticker := time.NewTicker(5 * time.Second)
					defer ticker.Stop()
					finalizeLaunches(gateCtx, gate.Admit, b.FinalizeLaunches, ticker.C)
				}()
				gate.Run(gateCtx)
				<-finalized
			}()
		}
		h, err := regionapi.New(regionapi.Config{
			Backend: b.Set(), Capabilities: b, Region: identity.Region.Name, Status: b, Pools: b,
			Gate: gated.Load(), CheckScope: proxmox.ScopeCheck(b),
			Version: regionapi.Version{ReleaseLine: "1.0", ClusterName: identity.ClusterName},
		})
		if err == nil {
			state.Store(&h)
		}
		return err
	}, now: time.Now, ttl: readyTTL}
	opsDone := make(chan error, 1)
	go func() {
		opsDone <- server.Serve(ctx, server.Options{
			Logger: slog.Default(), OpsAddr: *opsAddr,
			RegionAPINode: func() string {
				if gate := gated.Load(); gate != nil {
					return gate.APINode()
				}
				return ""
			},
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
	// deregister removes the registration first. If that fails nothing else
	// changes, so the region keeps working and the call can be retried. After
	// it, the quorum gate and launch finalizer are stopped and waited for (the
	// finalizer ends on the cancelled context and the wait covers its last PVE
	// write), the region API is withdrawn and the readiness cache is dropped, so
	// /readyz says unregistered at once. A request already past the gate may
	// finish; none starts. probe.mu orders this against Ready; Register may run
	// meanwhile, and its result is picked up by the next Ready.
	deregister := func(_ context.Context, data json.RawMessage) error {
		probe.mu.Lock()
		defer probe.mu.Unlock()
		if err := conn.Deregister(data); err != nil {
			return err
		}
		if gateCancel != nil {
			gateCancel()
			<-gateDone
		}
		gateCancel, gateDone, gateBackend = nil, nil, nil
		gated.Store(nil)
		state.Store(nil)
		probe.at = time.Time{}
		return nil
	}
	// Registration, deregistration and the connection test work before the region is ready.
	h := regionapi.WithRegistration(conn.Register, regionapi.WithDeregistration(deregister,
		regionapi.WithConnectionTest(conn.TestConnection,
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				current := state.Load()
				if current == nil {
					regionapi.WriteNotReady(w, probe.Ready(r.Context()))
					return
				}
				(*current).ServeHTTP(w, r)
			}))))
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
	reloadDone := make(chan struct{})
	go func() {
		defer close(reloadDone)
		ticker := time.NewTicker(readyTTL)
		defer ticker.Stop()
		for {
			if err := probe.Ready(ctx); err != nil && ctx.Err() == nil {
				slog.Default().WarnContext(ctx, "region not ready", slog.String("reason", err.Error()))
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	<-ctx.Done()
	<-reloadDone
	probe.mu.Lock()
	if gateCancel != nil {
		gateCancel()
		<-gateDone
	}
	probe.mu.Unlock()
	initialized.Store(false)
	shutCtx, shutCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer shutCancel()
	err = errors.Join(err, srv.Shutdown(shutCtx))
	if serveErr := <-done; !errors.Is(serveErr, http.ErrServerClosed) {
		err = errors.Join(err, serveErr)
	}
	return err
}

func finalizeLaunches(
	ctx context.Context, admit func(context.Context) error,
	finalize func(context.Context, func(context.Context) error) error, ticks <-chan time.Time,
) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticks:
			if err := admit(ctx); err != nil {
				continue
			}
			if err := finalize(ctx, admit); err != nil && ctx.Err() == nil {
				if resource.IsUnsupported(resource.AsError(err)) {
					return
				}
				_ = report.Error(ctx, fmt.Errorf("finalize launches: %w", err)) //nolint:errcheck // reported; next tick resumes
			}
		}
	}
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
