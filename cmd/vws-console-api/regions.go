package main

import (
	"context"
	"slices"
	"sync"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/awssdk"
	"github.com/popododo0720/vws-console-api/internal/backend/regionclient"
	"github.com/popododo0720/vws-console-api/internal/backend/regionset"
	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/surface/regionapi"
)

type inventoryCatalog struct{ backend.RegionCatalog }

func (c inventoryCatalog) RegionCapabilities(ctx context.Context, region string) (resource.RegionCapabilities, error) {
	accounts, catalogErr := c.AWSAccounts(ctx)
	if catalogErr != nil {
		return resource.RegionCapabilities{}, &resource.Error{
			Code: resource.CodeUnavailable, Message: "region catalog unavailable",
		}
	}
	kind := resource.RegionKindProxmox
	if region != "all" && slices.ContainsFunc(accounts, func(account backend.AWSAccount) bool {
		return slices.Contains(account.AllowedRegions, region)
	}) {
		kind = resource.RegionKindAWS
	}
	return inventoryCapabilities(ctx, region, kind)
}

func inventoryCapabilities(
	ctx context.Context, region string, kind resource.RegionKind,
) (resource.RegionCapabilities, error) {
	doc, err := (backend.AllSupported{Kind: kind}).RegionCapabilities(ctx, region)
	if err != nil {
		return doc, err
	}
	if kind == resource.RegionKindAWS {
		for _, read := range resource.ReadActions() {
			if read != resource.ReadDescribeInstances {
				doc.Actions[read.CapabilityKey()] = resource.ActionCapability{
					State: resource.ActionEmpty, ReasonCode: "InventoryNotImplemented", Reason: "AWS read is not implemented",
				}
			}
		}
	}
	return doc, nil
}

func (c inventoryCatalog) ProxmoxRegions(ctx context.Context) ([]backend.ProxmoxRegion, error) {
	regions, err := c.RegionCatalog.ProxmoxRegions(ctx)
	if err != nil {
		return nil, err
	}
	accounts, err := c.AWSAccounts(ctx)
	if err != nil {
		return nil, err
	}
	for _, account := range accounts {
		for _, name := range account.AllowedRegions {
			if !slices.ContainsFunc(regions, func(r backend.ProxmoxRegion) bool { return r.Name == name }) {
				regions = append(regions, backend.ProxmoxRegion{Name: name})
			}
		}
	}
	return regions, nil
}

func registeredBackends(catalog backend.RegionCatalog, connect func(string) (*regionapi.Client, error),
	socket string,
) (cloud.Config, func(), error) {
	var mu sync.Mutex
	clients := map[string]*regionapi.Client{}
	clientFor := func(endpoint string) (*regionapi.Client, error) {
		mu.Lock()
		defer mu.Unlock()
		if client := clients[endpoint]; client != nil {
			return client, nil
		}
		client, err := connect(endpoint)
		if err != nil {
			return nil, err
		}
		clients[endpoint] = client
		return client, nil
	}
	set, err := regionset.New(inventoryCatalog{RegionCatalog: catalog}, func(
		_ context.Context, region backend.ProxmoxRegion,
	) (regionclient.Transport, error) {
		if region.Endpoint == "" {
			return awsInventory{catalog: catalog, socket: socket}, nil
		}
		return clientFor(region.Endpoint)
	})
	cfg := cloud.Config{
		Backends: set, Regions: catalog,
		Discovery: func(ctx context.Context, region backend.ProxmoxRegion) (resource.RegionCapabilities, error) {
			if region.Kind == resource.RegionKindAWS {
				return inventoryCapabilities(ctx, region.Name, region.Kind)
			}
			client, err := clientFor(region.Endpoint)
			if err != nil {
				return resource.RegionCapabilities{}, err
			}
			return client.Capabilities(ctx)
		},
	}
	return cfg, func() {
		mu.Lock()
		defer mu.Unlock()
		for _, client := range clients {
			client.Close()
		}
	}, err
}

type awsInventory struct {
	catalog backend.RegionCatalog
	socket  string
}

func (a awsInventory) Call(ctx context.Context, service, method string, scope backend.Scope, req, dst any) error {
	accounts, err := a.catalog.AWSAccounts(ctx)
	if err != nil {
		return err
	}
	if !slices.ContainsFunc(accounts, func(account backend.AWSAccount) bool {
		return account.ID == scope.Account.String() && slices.Contains(account.AllowedRegions, scope.Region)
	}) {
		return resource.Invalid("account", "no registered AWS account for this region")
	}
	if service != "Compute" || method != "DescribeInstances" {
		return resource.Unsupported("Action", "AWS inventory does not serve this read")
	}
	client, err := awssdk.New(awssdk.Config{
		Socket: a.socket, Account: scope.Account.String(), Region: scope.Region,
		Principal: func(context.Context) string { return scope.Principal },
	})
	if err != nil {
		return err
	}
	defer client.Close()
	query, queryOK := req.(resource.InstanceQuery)
	result, resultOK := dst.(*resource.Page[resource.Instance])
	if !queryOK || !resultOK {
		return resource.Invalid("request", "invalid AWS instance inventory request")
	}
	page, err := client.DescribeInstances(ctx, scope, query)
	if err != nil {
		return err
	}
	*result = page
	return nil
}
