package pveclient

import (
	"context"
	"net/http"
	"net/url"
)

// CreateFirewallGroup adds a cluster security group; PVE refuses a taken name.
func (c *Client) CreateFirewallGroup(ctx context.Context, group, comment string) error {
	if _, err := segment("group", group); err != nil {
		return err
	}
	return c.VolumeWrite(ctx, http.MethodPost, "/cluster/firewall/groups",
		url.Values{"group": {group}, "comment": {comment}}, nil)
}

// DeleteFirewallGroup removes a cluster security group that holds no rules.
func (c *Client) DeleteFirewallGroup(ctx context.Context, group string) error {
	g, err := segment("group", group)
	if err != nil {
		return err
	}
	return c.VolumeWrite(ctx, http.MethodDelete, "/cluster/firewall/groups"+g, nil, nil)
}
