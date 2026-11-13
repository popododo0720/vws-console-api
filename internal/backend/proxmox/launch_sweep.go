package proxmox

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/proxmox/pveclient"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func (b *Backend) launchNow() time.Time {
	if b.cfg.Now != nil {
		return b.cfg.Now()
	}
	return time.Now()
}

func (b *Backend) launchExpired(marker LaunchMarker) bool {
	now := b.launchNow()
	return marker.CreatedAt > 0 && marker.CreatedAt <= now.Unix() &&
		now.Sub(time.Unix(marker.CreatedAt, 0)) > 10*time.Minute
}

func (b *Backend) sweepLaunch(
	ctx context.Context, s backend.Scope, target pveclient.VM, marker LaunchMarker,
	expected []string, fence func(context.Context) error,
) error {
	for range 2 {
		// A retry or pool move can finish after the pass's inventory read,
		// including while a stop task is outstanding.
		vms, err := b.visibleVMs(ctx, s)
		if err != nil {
			return fmt.Errorf("read sweep inventory: %w", err)
		}
		index := slices.IndexFunc(vms, func(vm inventoryVM) bool {
			return vm.VMID == target.VMID && vm.Node == target.Node && vm.Pool == s.Pool && vm.Status != "unknown"
		})
		if index < 0 {
			return resource.Denied("proxmox: sweep VM left its pool or went offline")
		}
		cfg, err := b.client.VMConfig(ctx, target)
		if err != nil {
			return fmt.Errorf("read sweep config: %w", err)
		}
		current, found, err := ReadLaunchMarker(cfg.Description)
		if err != nil {
			return fmt.Errorf("read sweep marker: %w", err)
		}
		if !found || current.Key != marker.Key || current.UUID != marker.UUID ||
			current.Fingerprint != marker.Fingerprint || current.Index != marker.Index || current.Count != marker.Count ||
			current.Account != s.Account || cfg.Template == 1 || cfg.Lock != "" {
			return nil
		}
		tags := strings.Split(cfg.Tags, ";")
		if slices.Contains(tags, LaunchFailureTag) || slices.Contains(tags, "vws.holder") ||
			!b.launchExpired(current) ||
			!slices.ContainsFunc(expected, func(tag string) bool { return !slices.Contains(tags, tag) }) {
			return nil
		}
		action := "destroy"
		if vms[index].Status == "running" {
			action = "stop"
		}
		if err := fence(ctx); err != nil {
			return err
		}
		upid, err := b.client.Power(ctx, target, action, 0)
		if err != nil {
			return fmt.Errorf("submit launch sweep %s: %w", action, err)
		}
		if err := b.client.WaitTask(ctx, pveclient.Task{Node: target.Node, UPID: upid}, pveclient.StartWait); err != nil {
			return fmt.Errorf("wait launch sweep %s: %w", action, err)
		}
		if action == "destroy" {
			slog.InfoContext(ctx, "swept unfinalized launch", slog.Int("vmid", target.VMID), slog.String("node", target.Node))
			return nil
		}
	}
	return resource.Conflict(resource.KindInstance, "", "launch VM restarted during sweep")
}
