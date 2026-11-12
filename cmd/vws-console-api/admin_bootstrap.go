package main

import (
	"context"
	"errors"
	"flag"
	"fmt"

	adminsecret "github.com/popododo0720/vws-console-api/internal/admin/secret"
	"github.com/popododo0720/vws-console-api/internal/admin/store"
	"github.com/popododo0720/vws-console-api/internal/backend/grpcclient/iamclient"
)

// adminBootstrap holds the explicit alternatives to global.yaml bootstrap.
type adminBootstrap struct {
	store   string
	kekFile string
	mtls    iamclient.TLSFiles
}

func (b *adminBootstrap) flags(fs *flag.FlagSet) {
	fs.StringVar(&b.store, "admin-store", "",
		"admin registry override: memory loses registrations on restart; empty uses the backend default")
	fs.StringVar(&b.kekFile, "admin-kek-file", "", "admin KEK file with -admin-store memory; empty disables admin writes")
	fs.StringVar(&b.mtls.CAFile, "region-mtls-ca-file", "",
		"region mTLS CA file; requires cert and key files, conflicts with -global-config")
	fs.StringVar(&b.mtls.CertFile, "region-mtls-cert-file", "",
		"region mTLS client certificate; requires CA and key files, conflicts with -global-config")
	fs.StringVar(&b.mtls.KeyFile, "region-mtls-key-file", "",
		"region mTLS client key; requires CA and cert files, conflicts with -global-config")
}

func (b adminBootstrap) validate(path string) error {
	switch b.store {
	case "":
		if b.kekFile != "" {
			return errors.New("-admin-kek-file requires -admin-store memory")
		}
	case "memory":
		if path != "" {
			return errors.New("-admin-store memory conflicts with -global-config")
		}
	default:
		return fmt.Errorf("unknown -admin-store %q", b.store)
	}
	if b.mtls.Enabled() {
		if path != "" {
			return errors.New("-region-mtls-* conflicts with -global-config")
		}
		if b.mtls.CAFile == "" || b.mtls.CertFile == "" || b.mtls.KeyFile == "" {
			return errors.New("-region-mtls-ca-file, -region-mtls-cert-file and -region-mtls-key-file require all three files")
		}
	}
	return nil
}

func (b adminBootstrap) open(
	ctx context.Context, path, backendKind string,
) (*store.Registry, *adminsecret.Key, func() error, error) {
	if b.store == "" {
		return openRegistry(ctx, path, backendKind)
	}
	var key *adminsecret.Key
	if b.kekFile != "" {
		var err error
		key, err = adminsecret.LoadFile(b.kekFile)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("load -admin-kek-file: %w", err)
		}
	}
	return store.New(store.NewMemory()), key, func() error { return nil }, nil
}
