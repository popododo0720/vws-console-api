package cloud

import (
	"context"
	"fmt"
	"time"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// OpenConsole checks regional support and ownership before opening a console.
func (s *Service) OpenConsole(
	ctx context.Context, c resource.Caller, id resource.InstanceID, kind resource.ConsoleKind,
) (resource.ConsoleSession, error) {
	if err := requireCaller(c); err != nil {
		return resource.ConsoleSession{}, err
	}
	if id.IsZero() || (kind != resource.ConsoleVNC && kind != resource.ConsoleSerial) {
		return resource.ConsoleSession{}, resource.Invalid("console", "instance and vnc or serial kind are required")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	c.Region = s.capabilityRegion(c.Region)
	caps, err := s.caps.RegionCapabilities(ctx, c.Region)
	if err != nil {
		return resource.ConsoleSession{}, fmt.Errorf("console capabilities: %w", err)
	}
	capability := caps.Actions["vws:OpenConsole"]
	if capability.State != resource.ActionSupported && capability.State != resource.ActionPartial {
		return resource.ConsoleSession{}, resource.Unsupported("OpenConsole", capability.Reason)
	}
	page, err := readPage(ctx, c, resource.InstanceQuery{IDs: []resource.InstanceID{id}},
		s.backends.Compute.DescribeInstances)
	if err != nil {
		return resource.ConsoleSession{}, err
	}
	found := false
	for _, instance := range page.Items {
		found = found || instance.ID == id
	}
	if !found {
		return resource.ConsoleSession{}, resource.NotFound(resource.KindInstance, id.String())
	}
	session, err := s.backends.Console.OpenConsole(ctx, scope(c), id, kind)
	if err != nil {
		return resource.ConsoleSession{}, err
	}
	if session.Dial == nil {
		return resource.ConsoleSession{}, resource.Unsupported("OpenConsole", "console transport unavailable")
	}
	return session, nil
}
