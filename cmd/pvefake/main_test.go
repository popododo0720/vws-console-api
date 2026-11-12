package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCommandRejectsInvalidInput(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "pvefake")
	build := exec.CommandContext(t.Context(), "go", "build", "-o", binary, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	invalid := filepath.Join(dir, "invalid.yaml")
	if err := os.WriteFile(invalid, []byte("unknown: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"parse", []string{"-scenario", invalid}, "decode scenario"},
		{"missing_file", []string{"-scenario", filepath.Join(dir, "missing")}, "no such file"},
		{"invalid_scenario", []string{"-scenario", invalid, "-listen", "127.0.0.1:0"}, "field unknown"},
		{"wildcard", []string{"-listen", "0.0.0.0:0"}, "loopback IP"},
		{"wildcard_ipv6", []string{"-listen", "[::]:0"}, "loopback IP"},
		{"remote", []string{"-listen", "192.0.2.1:8006"}, "loopback IP"},
		{"hostname", []string{"-listen", "localhost:8006"}, "loopback IP"},
		{"missing_port", []string{"-listen", "127.0.0.1"}, "listen address"},
		{"invalid_port", []string{"-listen", "127.0.0.1:65536"}, "listen"},
		{"positional", []string{"unexpected"}, "no positional"},
		{"missing_ca", []string{"-ca-file="}, "expected -scenario and -ca-file"},
		{"missing_scenario", []string{"-scenario="}, "expected -scenario and -ca-file"},
		{"ca_directory", []string{"-listen", "127.0.0.1:0", "-ca-file", dir}, "write CA certificate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			args := append([]string{"-scenario", "testdata/scenario.yaml", "-ca-file", filepath.Join(dir, "ca.pem")}, tc.args...)
			out, err := exec.CommandContext(ctx, binary, args...).CombinedOutput()
			if err == nil || ctx.Err() != nil || !strings.Contains(string(out), tc.want) {
				t.Fatalf("err=%v output=%s; want refusal containing %q", err, out, tc.want)
			}
			if strings.Contains(string(out), "https://") {
				t.Fatal("refused command printed readiness")
			}
		})
	}
	if err := os.WriteFile(invalid, []byte("version: {version: '9.2', release: '9.2'}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.CommandContext(t.Context(), binary, "-scenario", invalid,
		"-ca-file", filepath.Join(dir, "ca.pem")).CombinedOutput()
	if err == nil || !strings.Contains(string(out), "no nodes") {
		t.Fatalf("scenario validation: %v %s", err, out)
	}
}

func TestDefaultListen(t *testing.T) {
	var output bytes.Buffer
	if err := run(t.Context(), []string{"-help"}, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `default "127.0.0.1:8006"`) {
		t.Fatalf("default listen missing from usage: %s", output.String())
	}
}
