package cloud

import (
	"context"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// maxAddressPages bounds the address scan behind one DescribeInstances.
const maxAddressPages = 20

// fillPublicIPs sets each instance's public IP from the elastic IP associated
// with it. Compute does not know about elastic IPs; the network service does.
// A network backend that has no addresses leaves the fields empty.
func (s *Service) fillPublicIPs(ctx context.Context, c resource.Caller, items []resource.Instance) error {
	if s.backends.Network == nil {
		return nil
	}
	byInstance := map[resource.InstanceID]resource.Address{}
	token := ""
	for range maxAddressPages {
		page, err := readPage(ctx, c, resource.AddressQuery{Page: resource.PageRequest{Size: 100, Token: token}}, s.backends.Network.DescribeAddresses)
		if resource.CodeOf(err) == resource.CodeUnimplemented {
			return nil
		}
		if err != nil {
			return err
		}
		for _, addr := range page.Items {
			if !addr.InstanceID.IsZero() && addr.PublicIP != "" {
				byInstance[addr.InstanceID] = addr
			}
		}
		token = page.NextToken
		if token == "" {
			break
		}
	}
	for i := range items {
		if addr, ok := byInstance[items[i].ID]; ok {
			items[i].PublicIP = addr.PublicIP
			items[i].PublicIPAllocationID = addr.ID
		}
	}
	return nil
}
