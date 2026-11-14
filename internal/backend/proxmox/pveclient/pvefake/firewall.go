package pvefake

import (
	"net/http"
	"regexp"
	"slices"
)

// FirewallGroup is a cluster firewall security group.
type FirewallGroup struct {
	Group   string `yaml:"group" json:"group"`
	Comment string `yaml:"comment" json:"comment"`
}

func (f *Fake) firewallRoutes() {
	f.handle("/cluster/firewall/groups", func(t *Token, _ *http.Request) (any, *failure) {
		if fail := f.need(t, "/", "Sys.Audit"); fail != nil {
			return nil, fail
		}
		return f.s.FirewallGroups, nil
	})
	f.handleMethod(http.MethodPost, "/cluster/firewall/groups", func(t *Token, r *http.Request) (any, *failure) {
		if fail := f.need(t, "/", "Sys.Modify"); fail != nil {
			return nil, fail
		}
		if err := r.ParseForm(); err != nil {
			return nil, parameter("body", "invalid form")
		}
		group := r.Form.Get("group")
		if !regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{1,17}$`).MatchString(group) {
			return nil, parameter("group", "invalid security group name")
		}
		if slices.ContainsFunc(f.s.FirewallGroups, func(g FirewallGroup) bool { return g.Group == group }) {
			return nil, parameter("group", "security group '"+group+"' already exists")
		}
		f.s.FirewallGroups = append(f.s.FirewallGroups, FirewallGroup{Group: group, Comment: r.Form.Get("comment")})
		return nil, nil
	})
	f.handleMethod(http.MethodDelete, "/cluster/firewall/groups/{group}", func(t *Token, r *http.Request) (any, *failure) {
		if fail := f.need(t, "/", "Sys.Modify"); fail != nil {
			return nil, fail
		}
		before := len(f.s.FirewallGroups)
		f.s.FirewallGroups = slices.DeleteFunc(f.s.FirewallGroups, func(g FirewallGroup) bool {
			return g.Group == r.PathValue("group")
		})
		if len(f.s.FirewallGroups) == before {
			return nil, parameter("group", "no such security group")
		}
		return nil, nil
	})
}
