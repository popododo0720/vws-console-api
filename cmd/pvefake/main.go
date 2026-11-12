// Command pvefake serves a YAML Proxmox scenario over loopback HTTPS.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient/pvefake"
)

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "pvefake: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, output io.Writer) (err error) {
	fs := flag.NewFlagSet("pvefake", flag.ContinueOnError)
	fs.SetOutput(output)
	scenario := fs.String("scenario", "", "YAML scenario file (required)")
	listen := fs.String("listen", "127.0.0.1:8006", "loopback IP address and port")
	caFile := fs.String("ca-file", "", "output CA certificate file (required)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return fmt.Errorf("flags: %w", err)
	}
	if fs.NArg() != 0 || *scenario == "" || *caFile == "" {
		return errors.New("expected -scenario and -ca-file, with no positional arguments")
	}
	host, _, err := net.SplitHostPort(*listen)
	if err != nil {
		return fmt.Errorf("listen address: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("listen address must use a loopback IP")
	}
	s, err := pvefake.Load(*scenario)
	if err != nil {
		return err
	}
	handler, err := pvefake.New(s)
	if err != nil {
		return err
	}
	cert, ca, err := certificate(ip)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", *listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer func() {
		if closeErr := ln.Close(); !errors.Is(closeErr, net.ErrClosed) {
			err = errors.Join(err, closeErr)
		}
	}()
	if err := os.WriteFile(*caFile, ca, 0o600); err != nil {
		return fmt.Errorf("write CA certificate: %w", err)
	}
	srv := &http.Server{
		Handler: handler, ReadHeaderTimeout: 5 * time.Second,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}},
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(tls.NewListener(ln, srv.TLSConfig)) }()
	if _, err := fmt.Fprintf(output, "https://%s\n", ln.Addr()); err != nil {
		return errors.Join(fmt.Errorf("write listen URL: %w", err), srv.Close(), <-done)
	}
	select {
	case err := <-done:
		return fmt.Errorf("serve HTTPS: %w", err)
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	shutdownErr := srv.Shutdown(shutdownCtx)
	if shutdownErr != nil {
		shutdownErr = errors.Join(shutdownErr, srv.Close())
	}
	if serveErr := <-done; !errors.Is(serveErr, http.ErrServerClosed) {
		return errors.Join(shutdownErr, fmt.Errorf("serve HTTPS: %w", serveErr))
	}
	if shutdownErr != nil {
		return fmt.Errorf("shutdown HTTPS: %w", shutdownErr)
	}
	return nil
}

func certificate(ip net.IP) (tls.Certificate, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("generate TLS key: %w", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "pvefake"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage:    x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{ip},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("create TLS certificate: %w", err)
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, ca, nil
}
