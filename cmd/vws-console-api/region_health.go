package main

import (
	"context"
	"crypto/tls"
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
	if path == "" {
		return func(context.Context, string) (resource.RegionStatus, error) {
			return resource.RegionStatus{}, &console.RegionMTLSConfigError{Err: errors.New("mTLS is not configured")}
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
	return func(ctx context.Context, endpoint string) (resource.RegionStatus, error) {
		config, err := (iamclient.TLSFiles{
			CAFile: files.CAFile, CertFile: files.CertFile, KeyFile: files.KeyFile,
		}).Config()
		if err != nil {
			return resource.RegionStatus{}, &console.RegionMTLSConfigError{Err: err}
		}
		cert, err := tls.LoadX509KeyPair(files.CertFile, files.KeyFile)
		if err != nil {
			return resource.RegionStatus{}, &console.RegionMTLSConfigError{Err: err}
		}
		config.Certificates = []tls.Certificate{cert}
		client, err := regionapi.NewClient(endpoint, config)
		if err != nil {
			return resource.RegionStatus{}, err
		}
		defer client.Close()
		return client.Status(ctx)
	}, nil
}
