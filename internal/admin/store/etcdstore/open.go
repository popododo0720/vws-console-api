package etcdstore

import (
	"context"
	"fmt"

	"go.etcd.io/etcd/client/pkg/v3/transport"
	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/popododo0720/vws-console-api/internal/admin/store"
	"github.com/popododo0720/vws-console-api/internal/globalconfig"
)

// Open connects the registry to the IAM etcd using bootstrap TLS files.
func Open(ctx context.Context, cfg globalconfig.IAM) (*store.Registry, func() error, error) {
	tlsInfo := transport.TLSInfo{TrustedCAFile: cfg.TLS.CAFile, CertFile: cfg.TLS.CertFile, KeyFile: cfg.TLS.KeyFile}
	tlsConfig, err := tlsInfo.ClientConfig()
	if err != nil {
		return nil, nil, fmt.Errorf("admin registry TLS: %w", err)
	}
	client, err := clientv3.New(clientv3.Config{
		Context: ctx, Endpoints: cfg.EtcdEndpoints, TLS: tlsConfig, DialTimeout: CallTimeout,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("open admin registry: %w", err)
	}
	return store.New(New(client)), func() error {
		if err := client.Close(); err != nil {
			return fmt.Errorf("close admin registry: %w", err)
		}
		return nil
	}, nil
}
