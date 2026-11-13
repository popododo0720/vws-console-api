package pvefake

import (
	"net/http"
	"regexp"
	"slices"
)

func (f *Fake) sdnRoutes() {
	f.handle("/cluster/sdn/zones", func(*Token, *http.Request) (any, *failure) {
		rows := []map[string]string{}
		for _, zone := range f.s.SDNZones {
			rows = append(rows, map[string]string{"zone": zone, "type": "simple"})
		}
		return rows, nil
	})
	f.handle("/cluster/sdn/vnets", func(*Token, *http.Request) (any, *failure) {
		return f.s.VNets, nil
	})
	f.handle("/cluster/sdn/vnets/{vnet}/subnets", func(_ *Token, r *http.Request) (any, *failure) {
		for _, v := range f.s.VNets {
			if v.Name == r.PathValue("vnet") {
				return v.Subnets, nil
			}
		}
		return nil, &failure{http.StatusNotFound, "vnet does not exist"}
	})
	f.handleMethod(http.MethodPost, "/cluster/sdn/vnets", func(t *Token, r *http.Request) (any, *failure) {
		if err := r.ParseForm(); err != nil {
			return nil, parameter("body", "invalid form")
		}
		name, zone := r.Form.Get("vnet"), r.Form.Get("zone")
		if !regexp.MustCompile(`^[a-z][a-z0-9]{0,7}$`).MatchString(name) || !slices.Contains(f.s.SDNZones, zone) {
			return nil, parameter("vnet", "invalid vnet or zone")
		}
		if fail := f.need(t, "/sdn/zones/"+zone, "SDN.Allocate"); fail != nil {
			return nil, fail
		}
		for _, v := range f.s.VNets {
			if v.Name == name {
				return nil, parameter("vnet", "already exists")
			}
		}
		f.s.VNets = append(f.s.VNets, VNet{Name: name, Zone: zone, Alias: r.Form.Get("alias"), State: "new"})
		return nil, nil
	})
	f.handleMethod(http.MethodDelete, "/cluster/sdn/vnets/{vnet}", func(t *Token, r *http.Request) (any, *failure) {
		for i, v := range f.s.VNets {
			if v.Name != r.PathValue("vnet") {
				continue
			}
			if fail := f.need(t, "/sdn/zones/"+v.Zone, "SDN.Allocate"); fail != nil {
				return nil, fail
			}
			if len(v.Subnets) != 0 {
				return nil, parameter("vnet", "subnets still exist")
			}
			f.s.VNets[i].State = "deleted"
			return nil, nil
		}
		return nil, &failure{http.StatusNotFound, "vnet does not exist"}
	})
	f.handleMethod(http.MethodPut, "/cluster/sdn", func(t *Token, _ *http.Request) (any, *failure) {
		if fail := f.need(t, "/sdn", "SDN.Allocate"); fail != nil {
			return nil, fail
		}
		if !f.quorate {
			return nil, &failure{http.StatusInternalServerError, "cluster not ready - no quorum?"}
		}
		return f.submit(t, f.s.Nodes[0].Name, "sdnapply", "", func() string {
			f.s.VNets = slices.DeleteFunc(f.s.VNets, func(v VNet) bool { return v.State == "deleted" })
			for i := range f.s.VNets {
				f.s.VNets[i].State = ""
			}
			return "OK"
		}), nil
	})
}
