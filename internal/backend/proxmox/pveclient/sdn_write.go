package pveclient

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// CreateVNet allocates pending SDN configuration. Replay recovers from inventory.
func (c *Client) CreateVNet(ctx context.Context, vnet, zone, alias string) error {
	if _, err := segment("vnet", vnet); err != nil {
		return err
	}
	if _, err := segment("zone", zone); err != nil {
		return err
	}
	return c.VolumeWrite(ctx, http.MethodPost, "/cluster/sdn/vnets",
		url.Values{"vnet": {vnet}, "zone": {zone}, "alias": {alias}}, nil)
}

// DeleteVNet marks pending configuration for removal.
func (c *Client) DeleteVNet(ctx context.Context, vnet string) error {
	v, err := segment("vnet", vnet)
	if err != nil {
		return err
	}
	return c.VolumeWrite(ctx, http.MethodDelete, "/cluster/sdn/vnets"+v, nil, nil)
}

// ApplySDN waits for the cluster to activate pending configuration.
func (c *Client) ApplySDN(ctx context.Context) error {
	var upid string
	if err := c.VolumeWrite(ctx, http.MethodPut, "/cluster/sdn", nil, &upid); err != nil {
		return err
	}
	parts := strings.Split(upid, ":")
	if len(parts) < 3 || parts[0] != "UPID" {
		return fmt.Errorf("pveclient: invalid SDN apply UPID %q", upid)
	}
	return c.WaitTask(ctx, Task{Node: parts[1], UPID: upid}, CloneWait)
}
