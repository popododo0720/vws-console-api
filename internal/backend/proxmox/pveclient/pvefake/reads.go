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
	f.handle("/nodes/{node}/network", f.network)
	f.handle("/nodes/{node}/qemu/{vmid}/config", f.config)
	f.handle("/access/permissions", f.permissions)
	f.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		msg := fmt.Sprintf("Method '%s %s' not implemented", r.Method, r.URL.Path)
		reply(w, nil, &failure{http.StatusNotImplemented, msg})
	})
}

func (f *Fake) network(t *Token, r *http.Request) (any, *failure) {
	node, fail := f.node(r)
	if fail != nil {
		return nil, fail
	}
	if fail := f.need(t, "/nodes/"+node, "Sys.Audit"); fail != nil {
		return nil, fail
	}
	kind := r.URL.Query().Get("type")
	if kind != "" && kind != "any_bridge" {
		return nil, &failure{http.StatusBadRequest, "Parameter verification failed. type: unsupported type"}
	}
	rows := []map[string]any{}
	for _, n := range f.s.Networks {
		if n.Node != node || (kind == "any_bridge" && n.Type != "bridge" && n.Type != "OVSBridge") {
			continue
		}
		row := map[string]any{"iface": n.Iface, "type": n.Type}
		setIf(row, "cidr", n.CIDR)
		rows = append(rows, row)
	}
	return rows, nil
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
			"type": "node", "id": "node/" + n.Name, "name": n.Name, "nodeid": (i + 1) * b2i(f.s.Cluster != ""), "level": "",
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
	if kind == "" || kind == "storage" {
		for _, s := range f.s.Storages {
			if f.can(t, "/storage/"+s.Name, "Datastore.Audit") {
				rows = append(rows, map[string]any{
					"type": "storage", "storage": s.Name, "node": s.Node,
					"id": "storage/" + s.Node + "/" + s.Name,
				})
			}
		}
	}
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
			if vm.Pool != "" && f.can(t, "/pool/"+vm.Pool, "Pool.Audit") {
				row["pool"] = vm.Pool
			}
			setIf(row, "tags", vm.Tags)
			rows = append(rows, row)
		}
	}
	for _, n := range f.s.Nodes {
		if kind == "" || kind == "node" {
			rows = append(rows, f.nodeRow(t, n))
		}
	}
	return rows, nil
}

// nodeRow is a node as /nodes and /cluster/resources list it, for every
// caller. Without Sys.Audit on the node the stats are left out, and an
// offline node has no live ones (API2Tools::extract_node_stats).
func (f *Fake) nodeRow(t *Token, n Node) map[string]any {
	online := f.online[n.Name]
	row := map[string]any{"id": "node/" + n.Name, "type": "node", "node": n.Name, "status": "offline", "level": ""}
	if online {
		row["status"] = "online"
	}
	if !f.can(t, "/nodes/"+n.Name, "Sys.Audit") {
		return row
	}
	row["maxcpu"], row["maxmem"] = n.MaxCPU, n.MaxMem
	if online {
		row["mem"], row["cpu"], row["uptime"] = 0, 0, 0
	}
	return row
}

func (f *Fake) nodes(t *Token, _ *http.Request) (any, *failure) {
	rows := []map[string]any{}
	for _, n := range f.s.Nodes {
		rows = append(rows, f.nodeRow(t, n))
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
		if k == "cores" || k == "sockets" || k == "memory" {
			if n, err := strconv.Atoi(v); err == nil {
				cfg[k] = n
			}
		}
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

// permissions answers for the path asked or, as get_effective_permissions
// does, for the fixed top paths, every node of the ACL tree of any token and
// every pool member, leaving out the paths t holds nothing on.
func (f *Fake) permissions(t *Token, r *http.Request) (any, *failure) {
	out := map[string]map[string]int{}
	if p := r.URL.Query().Get("path"); p != "" {
		out[p] = f.privs(t, p)
		return out, nil
	}
	paths := []string{"/", "/access", "/access/groups", "/nodes", "/pool", "/sdn", "/storage", "/vms"}
	for _, tok := range f.s.Tokens {
		for _, a := range tok.ACL {
			paths = append(paths, levels(a.Path)...)
		}
	}
	for _, vm := range f.s.VMs {
		if vm.Pool != "" {
			paths = append(paths, "/vms/"+strconv.Itoa(vm.VMID))
		}
	}
	for _, p := range paths {
		if held := f.privs(t, p); len(held) > 0 {
			out[p] = held
		}
	}
	return out, nil
}
