package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/popododo0720/vws-console-api/internal/backend/grpcclient/iamclient"
	"github.com/popododo0720/vws-console-api/internal/globalconfig"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/surface/console"
	"github.com/popododo0720/vws-console-api/internal/surface/regionapi"
)

func regionHealth(files iamclient.TLSFiles) func(context.Context, string) (resource.RegionStatus, error) {
	connect := regionConnection(files)
	return func(ctx context.Context, endpoint string) (resource.RegionStatus, error) {
		client, err := connect(endpoint)
		if err != nil {
			return resource.RegionStatus{}, err
		}
		defer client.Close()
		return client.Status(ctx)
	}
}

func regionRegistration(files iamclient.TLSFiles) func(context.Context, string, json.RawMessage) error {
	connect := regionConnection(files)
	return func(ctx context.Context, endpoint string, data json.RawMessage) error {
		client, err := connect(endpoint)
		if err != nil {
			return err
		}
		defer client.Close()
		return client.Register(ctx, data)
	}
}

func regionPool(files iamclient.TLSFiles) func(context.Context, string, string) (bool, error) {
	connect := regionConnection(files)
	return func(ctx context.Context, endpoint, pool string) (bool, error) {
		client, err := connect(endpoint)
		if err != nil {
			return false, err
		}
		defer client.Close()
		return client.PoolExists(ctx, pool)
	}
}

func regionMTLSFiles(path string, files iamclient.TLSFiles) (iamclient.TLSFiles, error) {
	if path == "" {
		return files, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return iamclient.TLSFiles{}, fmt.Errorf("read region mTLS bootstrap: %w", err)
	}
	cfg, err := globalconfig.Parse(data)
	if err != nil {
		return iamclient.TLSFiles{}, fmt.Errorf("parse region mTLS bootstrap: %w", err)
	}
	return iamclient.TLSFiles{
		CAFile: cfg.Credentials.MTLS.CAFile, CertFile: cfg.Credentials.MTLS.CertFile, KeyFile: cfg.Credentials.MTLS.KeyFile,
	}, nil
}

func regionConnection(files iamclient.TLSFiles) func(string) (*regionapi.Client, error) {
	if !files.Enabled() {
		return func(string) (*regionapi.Client, error) {
			return nil, &console.RegionMTLSConfigError{Err: errors.New("mTLS is not configured")}
		}
	}
	return func(endpoint string) (*regionapi.Client, error) {
		config, err := files.Config()
		if err != nil {
			return nil, &console.RegionMTLSConfigError{Err: err}
		}
		cert, err := tls.LoadX509KeyPair(files.CertFile, files.KeyFile)
		if err != nil {
			return nil, &console.RegionMTLSConfigError{Err: err}
		}
		config.Certificates = []tls.Certificate{cert}
		return regionapi.NewClient(endpoint, config)
	}
}
