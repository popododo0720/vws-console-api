package proxmox

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func mutationFunctions(t *testing.T) []*ast.FuncDecl {
	t.Helper()
	files, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var functions []*ast.FuncDecl
	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".go") || strings.HasSuffix(file.Name(), "_test.go") {
			continue
		}
		tree, err := parser.ParseFile(token.NewFileSet(), file.Name(), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range tree.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			for _, param := range fn.Type.Params.List {
				if selectorIs(param.Type, "backend", "Mutation") {
					functions = append(functions, fn)
					break
				}
			}
		}
	}
	if len(functions) == 0 {
		t.Fatal("found no mutation methods")
	}
	return functions
}

func selectorIs(expr ast.Expr, receiver, name string) bool {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != name {
		return false
	}
	x, ok := sel.X.(*ast.Ident)
	return ok && x.Name == receiver
}

func unsupportedMutation(fn *ast.FuncDecl) bool {
	if fn.Body == nil || len(fn.Body.List) != 1 {
		return false
	}
	ret, ok := fn.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(ret.Results) == 0 {
		return false
	}
	call, ok := ret.Results[len(ret.Results)-1].(*ast.CallExpr)
	if !ok || !selectorIs(call.Fun, "resource", "Unsupported") {
		return false
	}
	calls := 0
	ast.Inspect(ret, func(node ast.Node) bool {
		if _, ok := node.(*ast.CallExpr); ok {
			calls++
		}
		return true
	})
	return calls == 1
}

func firstMutationCall(fn *ast.FuncDecl) *ast.CallExpr {
	if fn.Body == nil || len(fn.Body.List) == 0 {
		return nil
	}
	var expr ast.Expr
	switch first := fn.Body.List[0].(type) {
	case *ast.AssignStmt:
		if len(first.Rhs) == 1 {
			expr = first.Rhs[0]
		}
	case *ast.ExprStmt:
		expr = first.X
	case *ast.IfStmt:
		if init, ok := first.Init.(*ast.AssignStmt); ok && len(init.Rhs) == 1 {
			expr = init.Rhs[0]
		}
	case *ast.ReturnStmt:
		if len(first.Results) == 1 {
			expr = first.Results[0]
		}
	}
	call, _ := expr.(*ast.CallExpr)
	return call
}

func TestEveryMutationChecksPool(t *testing.T) {
	for _, fn := range mutationFunctions(t) {
		if unsupportedMutation(fn) {
			continue
		}
		if !mutationGuardFirst(fn) {
			t.Errorf("%s: first statement must call a mutation pool guard", fn.Name.Name)
		}
	}
}

func mutationGuardFirst(fn *ast.FuncDecl) bool {
	call := firstMutationCall(fn)
	if call == nil {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	switch sel.Sel.Name {
	case "vmForMutation", "volumeForMutation", "snapshotForMutation", "poolForMutation":
		return true
	default:
		return false
	}
}

func TestMutationMethodsRejectOtherPools(t *testing.T) {
	cases := map[string]func(*testing.T, *Backend) (resource.Kind, string, error){
		"StartInstances": func(t *testing.T, b *Backend) (resource.Kind, string, error) {
			return powerCrossPool(t, b, "start")
		},
		"StopInstances": func(t *testing.T, b *Backend) (resource.Kind, string, error) {
			return powerCrossPool(t, b, "shutdown")
		},
		"RebootInstances": func(t *testing.T, b *Backend) (resource.Kind, string, error) {
			return powerCrossPool(t, b, "reboot")
		},
		"TerminateInstances": func(t *testing.T, b *Backend) (resource.Kind, string, error) {
			return powerCrossPool(t, b, "destroy")
		},
		"CreateTags": func(t *testing.T, b *Backend) (resource.Kind, string, error) {
			iid, _ := tagMutationIDs()
			_, err := b.CreateTags(t.Context(), backend.Mutation{Scope: inventoryScope()},
				resource.CreateTagsRequest{IDs: []resource.InstanceID{iid}, Tags: map[string]string{"env": "dev"}})
			return resource.KindInstance, iid.String(), err
		},
		"DeleteTags": func(t *testing.T, b *Backend) (resource.Kind, string, error) {
			iid, _ := tagMutationIDs()
			_, err := b.DeleteTags(t.Context(), backend.Mutation{Scope: inventoryScope()},
				resource.DeleteTagsRequest{IDs: []resource.InstanceID{iid}})
			return resource.KindInstance, iid.String(), err
		},
		"TagVolumes": func(t *testing.T, b *Backend) (resource.Kind, string, error) {
			_, vid := tagMutationIDs()
			_, err := b.TagVolumes(t.Context(), backend.Mutation{Scope: inventoryScope()},
				resource.TagVolumesRequest{IDs: []resource.VolumeID{vid}, Tags: map[string]string{"env": "dev"}})
			return resource.KindVolume, vid.String(), err
		},
		"UntagVolumes": func(t *testing.T, b *Backend) (resource.Kind, string, error) {
			_, vid := tagMutationIDs()
			_, err := b.UntagVolumes(t.Context(), backend.Mutation{Scope: inventoryScope()},
				resource.UntagVolumesRequest{IDs: []resource.VolumeID{vid}})
			return resource.KindVolume, vid.String(), err
		},
		"CreateVolume": func(t *testing.T, b *Backend) (resource.Kind, string, error) {
			_, err := b.CreateVolume(t.Context(), backend.Mutation{Scope: inventoryScope()}, resource.CreateVolumeRequest{})
			return resource.KindVolume, "", err
		},
		"DeleteVolume": func(t *testing.T, b *Backend) (resource.Kind, string, error) {
			id, _ := resource.Parse[resource.VolumeID]("vol-0123456789abcdef0")
			_, err := b.DeleteVolume(t.Context(), backend.Mutation{Scope: inventoryScope()},
				resource.DeleteVolumeRequest{ID: id})
			return resource.KindVolume, id.String(), err
		},
	}
	functions := mutationFunctions(t)
	implemented := map[string]bool{}
	for _, fn := range functions {
		if unsupportedMutation(fn) {
			continue
		}
		name := fn.Name.Name
		implemented[name] = true
		run, ok := cases[name]
		if !ok {
			t.Errorf("%s: missing cross-pool mutation case", name)
			continue
		}
		t.Run(name, func(t *testing.T) {
			s := mutationScenario()
			s.VMs[0].Pool = "999999999999"
			b, _ := networkBackend(t, s, RegionConfig{})
			kind, id, err := run(t, b)
			if name == "CreateVolume" {
				if resource.CodeOf(err) != resource.CodePermissionDenied {
					t.Fatalf("create without caller pool: %v", err)
				}
				return
			}
			assertMutationNotFound(t, err, kind, id)
		})
	}
	for name := range cases {
		if !implemented[name] {
			t.Errorf("%s: cross-pool case has no implemented mutation", name)
		}
	}
}

func TestMutationASTBoundaries(t *testing.T) {
	for _, tc := range []struct {
		body        string
		unsupported bool
		guard       bool
	}{
		{`return nil, resource.Unsupported("x", "read-only")`, true, false},
		{`b.write(); return nil, resource.Unsupported("x", "read-only")`, false, false},
		{`return b.write(), resource.Unsupported("x", "read-only")`, false, false},
		{`return nil, nil`, false, false},
		{`defer b.vmForMutation(ctx, m.Scope, id); return nil, nil`, false, false},
		{`if true { b.vmForMutation(ctx, m.Scope, id) }; return nil, nil`, false, false},
		{`vm, err := b.vmForMutation(ctx, m.Scope, id); return vm, err`, false, true},
		{`if _, err := b.vmForMutation(ctx, m.Scope, id); err != nil { return nil, err }; return nil, nil`, false, true},
	} {
		tree, err := parser.ParseFile(token.NewFileSet(), "", "package proxmox; func f() {"+tc.body+"}", 0)
		if err != nil {
			t.Fatal(err)
		}
		fn := tree.Decls[0].(*ast.FuncDecl)
		if got := unsupportedMutation(fn); got != tc.unsupported {
			t.Errorf("%s: unsupported=%v", tc.body, got)
		}
		if got := mutationGuardFirst(fn); got != tc.guard {
			t.Errorf("%s: first call=%v", tc.body, got)
		}
	}
}
