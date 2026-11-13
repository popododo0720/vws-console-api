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

// MoveVM changes pool membership between inventory calls.
func (f *Fake) MoveVM(vmid int, pool string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	vm := f.vm(vmid)
	if vm == nil {
		return fmt.Errorf("pvefake: unknown VM %d", vmid)
	}
	vm.Pool = pool
	return nil
}

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
	f.handle("/pools/{pool}", f.pool)
	f.handle("/nodes/{node}/network", f.network)
	f.handle("/nodes/{node}/qemu/{vmid}/config", f.config)
	f.handle("/nodes/{node}/qemu/{vmid}/snapshot", f.snapshots)
	f.handle("/nodes/{node}/storage/{storage}/content", f.storageContent)
	f.handle("/access/permissions", f.permissions)
	f.taskRoutes()
	f.writeRoutes()
	f.consoleRoutes()
	f.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		msg := fmt.Sprintf("Method '%s %s' not implemented", r.Method, r.URL.Path)
		reply(w, nil, &failure{http.StatusNotImplemented, msg})
	})
}

func (f *Fake) pool(t *Token, r *http.Request) (any, *failure) {
	name := r.PathValue("pool")
	if fail := f.need(t, "/pool/"+name, "Pool.Audit"); fail != nil {
		return nil, fail
	}
	exists := slices.Contains(f.s.Pools, name)
	members := []map[string]any{}
	for _, vm := range f.s.VMs {
		if vm.Pool == name {
			exists = true
			if f.can(t, "/vms/"+strconv.Itoa(vm.VMID), "VM.Audit") {
				members = append(members, map[string]any{
					"type": "qemu", "vmid": vm.VMID, "node": vm.Node, "id": "qemu/" + strconv.Itoa(vm.VMID),
				})
			}
		}
	}
	if !exists {
		return nil, &failure{http.StatusInternalServerError, fmt.Sprintf("pool '%s' does not exist", name)}
	}
	return map[string]any{"members": members}, nil
}

func (f *Fake) snapshots(t *Token, r *http.Request) (any, *failure) {
	vm, fail := f.guest(t, r)
	if fail != nil {
		return nil, fail
	}
	return append([]Snapshot{{Name: "current"}}, vm.Snapshots...), nil
}

func (f *Fake) storageContent(t *Token, r *http.Request) (any, *failure) {
	node, fail := f.node(r)
	if fail != nil {
		return nil, fail
	}
	name := r.PathValue("storage")
	if fail := f.need(t, "/storage/"+name, "Datastore.Audit"); fail != nil {
		return nil, fail
	}
	for _, storage := range f.s.Storages {
		if storage.Node == node && storage.Name == name {
			return append([]StorageContent{}, storage.Content...), nil
		}
	}
	return nil, &failure{http.StatusInternalServerError, fmt.Sprintf("storage '%s' does not exist", name)}
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
					"id":     "storage/" + s.Node + "/" + s.Name,
					"shared": s.Shared, "maxdisk": s.MaxDisk, "disk": s.Disk,
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
	return configRow(vm), nil
}

func configRow(vm *VM) map[string]any {
	cfg := map[string]any{}
	for k, v := range vm.Config {
		cfg[k] = v
		if k == "cores" || k == "sockets" || k == "memory" || k == "protection" {
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
	return cfg
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
