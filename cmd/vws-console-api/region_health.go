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

func regionHealth(path string) (func(context.Context, string) (resource.RegionStatus, error), error) {
	connect, err := regionConnection(path)
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context, endpoint string) (resource.RegionStatus, error) {
		client, err := connect(endpoint)
		if err != nil {
			return resource.RegionStatus{}, err
		}
		defer client.Close()
		return client.Status(ctx)
	}, nil
}

func regionRegistration(path string) (func(context.Context, string, json.RawMessage) error, error) {
	connect, err := regionConnection(path)
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context, endpoint string, data json.RawMessage) error {
		client, err := connect(endpoint)
		if err != nil {
			return err
		}
		defer client.Close()
		return client.Register(ctx, data)
	}, nil
}

func regionPool(path string) (func(context.Context, string, string) (bool, error), error) {
	connect, err := regionConnection(path)
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context, endpoint, pool string) (bool, error) {
		client, err := connect(endpoint)
		if err != nil {
			return false, err
		}
		defer client.Close()
		return client.PoolExists(ctx, pool)
	}, nil
}

func regionConnection(path string) (func(string) (*regionapi.Client, error), error) {
	if path == "" {
		return func(string) (*regionapi.Client, error) {
			return nil, &console.RegionMTLSConfigError{Err: errors.New("mTLS is not configured")}
		}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read region mTLS bootstrap: %w", err)
	}
	cfg, err := globalconfig.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("parse region mTLS bootstrap: %w", err)
	}
	files := cfg.Credentials.MTLS
	return func(endpoint string) (*regionapi.Client, error) {
		config, err := (iamclient.TLSFiles{
			CAFile: files.CAFile, CertFile: files.CertFile, KeyFile: files.KeyFile,
		}).Config()
		if err != nil {
			return nil, &console.RegionMTLSConfigError{Err: err}
		}
		cert, err := tls.LoadX509KeyPair(files.CertFile, files.KeyFile)
		if err != nil {
			return nil, &console.RegionMTLSConfigError{Err: err}
		}
		config.Certificates = []tls.Certificate{cert}
		return regionapi.NewClient(endpoint, config)
	}, nil
}
