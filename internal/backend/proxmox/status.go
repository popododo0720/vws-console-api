package proxmox

import (
	"context"
	"time"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// Status reads PVE live and retains only the last failure in process memory.
func (b *Backend) Status(ctx context.Context) (resource.RegionStatus, error) {
	result, err := b.clusterStatus(ctx)
	if err != nil {
		return resource.RegionStatus{}, err
	}
	versionCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	version, err := b.client.Version(versionCtx)
	if err == nil {
		result.PVERelease = version.Version
	}
	if ctx.Err() != nil {
		return resource.RegionStatus{}, ctx.Err()
	}
	if leader := b.leader.Load(); leader != nil {
		if node := leader.Current(); node != "" {
			result.Leader = &node
		}
	}
	return result, nil
}

func (b *Backend) clusterStatus(ctx context.Context) (resource.RegionStatus, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
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
