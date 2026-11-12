package main

import (
	"context"
	"slices"
	"sync"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/awssdk"
	"github.com/popododo0720/vws-console-api/internal/backend/regionclient"
	"github.com/popododo0720/vws-console-api/internal/backend/regionset"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/surface/regionapi"
)

type inventoryCatalog struct{ backend.RegionCatalog }

func (c inventoryCatalog) RegionCapabilities(ctx context.Context, region string) (resource.RegionCapabilities, error) {
	doc, err := (backend.AllSupported{Kind: resource.RegionKindProxmox}).RegionCapabilities(ctx, region)
	accounts, catalogErr := c.AWSAccounts(ctx)
	if catalogErr != nil {
		return doc, &resource.Error{Code: resource.CodeUnavailable, Message: "region catalog unavailable"}
	}
	if region != "all" && slices.ContainsFunc(accounts, func(account backend.AWSAccount) bool {
		return slices.Contains(account.AllowedRegions, region)
	}) {
		doc.Kind = resource.RegionKindAWS
		for _, read := range resource.ReadActions() {
			if read != resource.ReadDescribeInstances {
				doc.Actions[read.CapabilityKey()] = resource.ActionCapability{
					State: resource.ActionEmpty, ReasonCode: "InventoryNotImplemented", Reason: "AWS read is not implemented",
				}
			}
		}
	}
	return doc, err
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
) (backend.Set, func(), error) {
	var mu sync.Mutex
	clients := map[string]*regionapi.Client{}
	set, err := regionset.New(inventoryCatalog{catalog}, func(
		_ context.Context, region backend.ProxmoxRegion,
	) (regionclient.Transport, error) {
		if region.Endpoint == "" {
			return awsInventory{catalog: catalog, socket: socket}, nil
		}
		mu.Lock()
		defer mu.Unlock()
		if client := clients[region.Endpoint]; client != nil {
			return client, nil
		}
		client, err := connect(region.Endpoint)
		if err != nil {
			return nil, err
		}
		clients[region.Endpoint] = client
		return client, nil
	})
	return set, func() {
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
