package pvefake

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
)

// routes registers the cluster, node, VM config and permission read paths of
// pveclient. Permissions follow the
// api-viewer: a "check" is a 403 without the privilege, "user: all" lists
// only what the token may see.
func (f *Fake) routes() {
	f.handle("/version", func(*Token, *http.Request) (any, *failure) {
		v := f.s.Version
		return map[string]any{"version": v.Version, "release": v.Release, "repoid": v.RepoID}, nil
	})
	f.handle("/cluster/status", f.clusterStatus)
	f.handle("/cluster/resources", f.clusterResources)
	f.handle("/nodes", f.nodes)
	f.handle("/nodes/{node}/qemu/{vmid}/config", f.config)
	f.handle("/access/permissions", f.permissions)
	f.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		msg := fmt.Sprintf("Method '%s %s' not implemented", r.Method, r.URL.Path)
		reply(w, nil, &failure{http.StatusNotImplemented, msg})
	})
}

func (f *Fake) clusterStatus(t *Token, _ *http.Request) (any, *failure) {
	if fail := f.need(t, "/", "Sys.Audit"); fail != nil {
		return nil, fail
	}
	var rows []map[string]any
	if f.s.Cluster != "" {
		rows = append(rows, map[string]any{
			"type": "cluster", "id": "cluster", "name": f.s.Cluster,
			"nodes": len(f.s.Nodes), "quorate": b2i(f.quorate), "version": len(f.s.Nodes),
		})
	}
	for i, n := range f.s.Nodes {
		rows = append(rows, map[string]any{
			"type": "node", "id": "node/" + n.Name, "name": n.Name, "nodeid": i + 1, "level": "",
			"online": b2i(f.online[n.Name]), "local": b2i(i == 0), "ip": fmt.Sprintf("192.0.2.%d", i+1),
		})
	}
	return rows, nil
}

func (f *Fake) clusterResources(t *Token, r *http.Request) (any, *failure) {
	kind := r.URL.Query().Get("type")
	if !slices.Contains([]string{"", "vm", "node", "storage", "sdn"}, kind) {
		return nil, &failure{http.StatusBadRequest, "Parameter verification failed. type: value '" + kind +
			"' does not have a value in the enumeration 'vm, storage, node, sdn'"}
	}
	rows := []map[string]any{}
	if kind == "" || kind == "vm" {
		for _, vm := range f.s.VMs {
			if !f.can(t, "/vms/"+strconv.Itoa(vm.VMID), "VM.Audit") {
				continue
			}
			row := map[string]any{
				"id": "qemu/" + strconv.Itoa(vm.VMID), "type": "qemu", "node": vm.Node, "vmid": vm.VMID,
				"name": vm.Name, "status": vm.Status, "template": b2i(vm.Template),
				"maxcpu": vm.MaxCPU, "maxmem": vm.MaxMem, "mem": 0, "cpu": 0, "uptime": 0,
			}
			if !f.online[vm.Node] {
				row["status"] = "unknown"
			}
			setIf(row, "pool", vm.Pool)
			setIf(row, "tags", vm.Tags)
			rows = append(rows, row)
		}
	}
	for _, n := range f.s.Nodes {
		if (kind == "" || kind == "node") && f.can(t, "/nodes/"+n.Name, "Sys.Audit") {
			rows = append(rows, map[string]any{
				"id": "node/" + n.Name, "type": "node", "node": n.Name, "status": nodeStatus(f.online[n.Name]),
				"maxcpu": n.MaxCPU, "maxmem": n.MaxMem, "level": "",
			})
		}
	}
	return rows, nil
}

func nodeStatus(online bool) string {
	if online {
		return "online"
	}
	return "offline"
}

func (f *Fake) nodes(*Token, *http.Request) (any, *failure) {
	rows := []map[string]any{}
	for _, n := range f.s.Nodes {
		rows = append(rows, map[string]any{
			"node": n.Name, "id": "node/" + n.Name, "type": "node", "status": nodeStatus(f.online[n.Name]),
			"maxcpu": n.MaxCPU, "maxmem": n.MaxMem, "mem": 0, "cpu": 0, "uptime": 0, "level": "",
		})
	}
	return rows, nil
}

func (f *Fake) config(t *Token, r *http.Request) (any, *failure) {
	vm, fail := f.guest(t, r)
	if fail != nil {
		return nil, fail
	}
	cfg := map[string]any{}
	for k, v := range vm.Config {
		cfg[k] = v
	}
	setIf(cfg, "name", vm.Name)
	setIf(cfg, "tags", vm.Tags)
	if vm.Template {
		cfg["template"] = 1
	}
	var text strings.Builder
	for _, k := range slices.Sorted(maps.Keys(cfg)) {
		text.WriteString(k + ": " + fmt.Sprint(cfg[k]) + "\n")
	}
	digest := sha1.Sum([]byte(text.String()))
	cfg["digest"] = hex.EncodeToString(digest[:])
	return cfg, nil
}

// permissions answers for the path asked, or for every path the token's ACL
// names.
func (f *Fake) permissions(t *Token, r *http.Request) (any, *failure) {
	out := map[string]map[string]int{}
	if p := r.URL.Query().Get("path"); p != "" {
		out[p] = f.privs(t, p)
		return out, nil
	}
	for _, a := range t.ACL {
		out[a.Path] = f.privs(t, a.Path)
	}
	return out, nil
}
