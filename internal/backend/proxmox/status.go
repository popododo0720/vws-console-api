package proxmox

import (
	"context"
	"time"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// Status reads PVE live and retains only the last failure in process memory.
func (b *Backend) Status(ctx context.Context) (resource.RegionStatus, error) {
	rows, err := b.client.ClusterStatus(ctx)
	if err != nil && ctx.Err() != nil {
		return resource.RegionStatus{}, ctx.Err()
	}
	result := resource.RegionStatus{Nodes: []resource.RegionNode{}}
	cluster, localOnline := false, false
	for _, row := range rows {
		switch row.Type {
		case "cluster":
			cluster, result.Quorate = true, row.Quorate == 1
		case "node":
			result.Nodes = append(result.Nodes, resource.RegionNode{Name: row.Name, Online: row.Online == 1})
			if row.Local == 1 {
				localOnline = row.Online == 1
			}
		}
	}
	if !cluster {
		result.Quorate = localOnline
	}
	b.statusMu.Lock()
	defer b.statusMu.Unlock()
	if err != nil {
		b.lastStatusError = &resource.RegionStatusError{
			Time: time.Now().UTC(), Message: b.client.Redact(err.Error()),
		}
	}
	if b.lastStatusError != nil {
		last := *b.lastStatusError
		result.LastError = &last
	}
	return result, nil
}
