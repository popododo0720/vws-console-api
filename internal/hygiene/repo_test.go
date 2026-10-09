package hygiene

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRepositoryRules(t *testing.T) {
	root := filepath.Join("..", "..")
	var failures []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		if d.IsDir() {
			switch d.Name() {
			case ".git", "helm", "k8s", "deploy":
				if d.Name() != ".git" {
					failures = append(failures, "deployment directory "+rel)
				}
				return filepath.SkipDir
			}
			return nil
		}
		base := d.Name()
		switch base {
		case "Dockerfile", "docker-compose.yml", "docker-compose.yaml", "Chart.yaml":
			failures = append(failures, "deployment file "+rel)
		}
		ext := strings.ToLower(filepath.Ext(base))
		switch ext {
		case ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp":
			failures = append(failures, "image file "+rel)
		}
		if ext == ".go" && !strings.HasSuffix(base, "_test.go") && !strings.HasPrefix(filepath.ToSlash(rel), "internal/backend/") {
			if msg := mintCall(path); msg != "" {
				failures = append(failures, rel+": "+msg)
			}
		}
		if isText(ext, base) && base != "LICENSE" && !strings.HasSuffix(base, ".pb.go") {
			body, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			low := strings.ToLower(string(body))
			if strings.Contains(low, brandPhrase()) || strings.Contains(low, vendorHost()) {
				failures = append(failures, "branding text in "+rel)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(failures) > 0 {
		t.Fatalf("repository rules:\n%s", strings.Join(failures, "\n"))
	}
}

func brandPhrase() string { return "Amazon Web " + "Services" }

func vendorHost() string { return "amazon" + "aws" }

func isText(ext, base string) bool {
	switch ext {
	case ".go", ".md", ".yml", ".yaml", ".proto", ".mod":
		return true
	}
	return base == "buf.yaml" || base == "buf.gen.yaml"
}

func mintCall(path string) string {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		return err.Error()
	}
	var hit string
	ast.Inspect(file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		ident, ok := sel.X.(*ast.Ident)
		if !ok || ident.Name != "resource" {
			return true
		}
		if sel.Sel.Name == "Mint" || sel.Sel.Name == "NewOperationID" {
			hit = sel.Sel.Name + " is only for backends"
		}
		return true
	})
	return hit
}
