package regionapi

import (
	"encoding/json"
	"fmt"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// These extensions belong only to the internal transport. The embedded model
// keeps its public JSON unchanged while the region caller receives every field.
type wireInstance struct {
	resource.Instance
	KeyPairID        resource.KeyPairID     `json:"keyPairId,omitzero"`
	UserData         string                 `json:"userData"`
	DetachingDevices []resource.BlockDevice `json:"detachingDevices"`
}

type wireSecurityGroup struct {
	resource.SecurityGroup
	Etag    string            `json:"etag"`
	Labels  map[string]string `json:"labels"`
	RuleIDs []string          `json:"ruleIds"`
}

func mapPage[A, B any](page resource.Page[A], convert func(A) B) resource.Page[B] {
	var items []B
	if page.Items != nil {
		items = make([]B, len(page.Items))
		for i, item := range page.Items {
			items[i] = convert(item)
		}
	}
	return resource.Page[B]{Items: items, NextToken: page.NextToken, Partial: page.Partial, Stale: page.Stale}
}

func encodeResult(value any) any {
	switch page := value.(type) {
	case resource.Accepted[resource.Instance]:
		items := mapPage(resource.Page[resource.Instance]{Items: page.Items}, func(i resource.Instance) wireInstance {
			return wireInstance{i, i.KeyPairID, i.UserData, i.DetachingDevices}
		})
		return resource.Accepted[wireInstance]{Operation: page.Operation, Items: items.Items}
	case resource.Accepted[resource.SecurityGroup]:
		items := mapPage(resource.Page[resource.SecurityGroup]{Items: page.Items}, func(
			g resource.SecurityGroup,
		) wireSecurityGroup {
			return wireSecurityGroup{g, g.Etag, g.Labels, g.RuleIDs}
		})
		return resource.Accepted[wireSecurityGroup]{Operation: page.Operation, Items: items.Items}
	case resource.Page[resource.Instance]:
		return mapPage(page, func(i resource.Instance) wireInstance {
			return wireInstance{i, i.KeyPairID, i.UserData, i.DetachingDevices}
		})
	case resource.Page[resource.SecurityGroup]:
		return mapPage(page, func(g resource.SecurityGroup) wireSecurityGroup {
			return wireSecurityGroup{g, g.Etag, g.Labels, g.RuleIDs}
		})
	default:
		return value
	}
}

func decodeResult(data []byte, dst any) error {
	switch out := dst.(type) {
	case *resource.Accepted[resource.Instance]:
		var accepted resource.Accepted[wireInstance]
		if err := json.Unmarshal(data, &accepted); err != nil {
			return fmt.Errorf("decode accepted instances: %w", err)
		}
		items := mapPage(resource.Page[wireInstance]{Items: accepted.Items}, func(w wireInstance) resource.Instance {
			i := w.Instance
			i.KeyPairID, i.UserData, i.DetachingDevices = w.KeyPairID, w.UserData, w.DetachingDevices
			return i
		})
		*out = resource.Accepted[resource.Instance]{Operation: accepted.Operation, Items: items.Items}
	case *resource.Accepted[resource.SecurityGroup]:
		var accepted resource.Accepted[wireSecurityGroup]
		if err := json.Unmarshal(data, &accepted); err != nil {
			return fmt.Errorf("decode accepted security groups: %w", err)
		}
		items := mapPage(resource.Page[wireSecurityGroup]{Items: accepted.Items}, func(
			w wireSecurityGroup,
		) resource.SecurityGroup {
			g := w.SecurityGroup
			g.Etag, g.Labels, g.RuleIDs = w.Etag, w.Labels, w.RuleIDs
			return g
		})
		*out = resource.Accepted[resource.SecurityGroup]{Operation: accepted.Operation, Items: items.Items}
	case *resource.Page[resource.Instance]:
		var page resource.Page[wireInstance]
		if err := json.Unmarshal(data, &page); err != nil {
			return fmt.Errorf("decode instances: %w", err)
		}
		*out = mapPage(page, func(w wireInstance) resource.Instance {
			i := w.Instance
			i.KeyPairID, i.UserData, i.DetachingDevices = w.KeyPairID, w.UserData, w.DetachingDevices
			return i
		})
	case *resource.Page[resource.SecurityGroup]:
		var page resource.Page[wireSecurityGroup]
		if err := json.Unmarshal(data, &page); err != nil {
			return fmt.Errorf("decode security groups: %w", err)
		}
		*out = mapPage(page, func(w wireSecurityGroup) resource.SecurityGroup {
			g := w.SecurityGroup
			g.Etag, g.Labels, g.RuleIDs = w.Etag, w.Labels, w.RuleIDs
			return g
		})
	default:
		if err := json.Unmarshal(data, dst); err != nil {
			return fmt.Errorf("decode resource: %w", err)
		}
	}
	return nil
}
