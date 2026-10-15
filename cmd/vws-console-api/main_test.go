package main

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestStopOnSIGTERM(t *testing.T) {
	for _, sig := range stopSignals() {
		if sig == syscall.SIGTERM || sig == os.Interrupt {
			continue
		}
		t.Fatalf("unexpected signal %v", sig)
	}
	found := false
	for _, sig := range stopSignals() {
		if sig == syscall.SIGTERM {
			found = true
		}
	}
	if !found {
		t.Fatal("SIGTERM does not stop the process")
	}
}

func TestGRPCRefusesDefaultCredentials(t *testing.T) {
	clearCredentialEnv(t)
	t.Setenv("VWS_ACCESS_KEY", "AKIDREAL")
	err := run(t.Context(), []string{"-backend=grpc"})
	if err == nil {
		t.Fatal("grpc backend started with the default console token and secret")
	}
	for _, want := range []string{"VWS_CONSOLE_TOKEN", "VWS_SECRET_KEY"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %s", err, want)
		}
	}
	if strings.Contains(err.Error(), "VWS_ACCESS_KEY") {
		t.Errorf("error %q names a credential that was given", err)
	}
}

func TestUnknownIAMModeIsRejected(t *testing.T) {
	err := run(t.Context(), []string{"-iam=bogus", "-ops-addr="})
	if err == nil || !strings.Contains(err.Error(), `unknown -iam "bogus"`) {
		t.Fatalf("err %v", err)
	}
}

func TestRootPasswordFileIsValidated(t *testing.T) {
	dir := t.TempDir()
	weak := filepath.Join(dir, "weak")
	if err := os.WriteFile(weak, []byte("short\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{
		filepath.Join(dir, "missing"): "-root-password-file",
		weak:                          "minimum length",
	} {
		err := run(t.Context(), []string{"-root-password-file", path, "-ops-addr="})
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err %v", path, err)
		}
		if err != nil && strings.Contains(err.Error(), "short") {
			t.Errorf("password leaked into the error: %v", err)
		}
	}
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	root := iam.NewStatic("AKIDEXAMPLE", "secret", account)
	good := filepath.Join(dir, "good")
	if err := os.WriteFile(good, []byte("root password 9\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := setRootPassword(t.Context(), root, good); err != nil {
		t.Fatal(err)
	}
	if _, err := root.Login(t.Context(), iam.LoginRequest{Account: account, UserName: iam.RootUserName, Password: "root password 9"}); err != nil {
		t.Errorf("the trailing newline was not dropped: %v", err)
	}
}

func TestBadTrustedProxiesIsRejected(t *testing.T) {
	err := run(t.Context(), []string{"-trusted-proxies=10.0.0.0/33", "-ops-addr="})
	if err == nil || !strings.Contains(err.Error(), "-trusted-proxies") || !strings.Contains(err.Error(), "10.0.0.0/33") {
		t.Fatalf("err %v", err)
	}
}

func TestGRPCIAMNeedsAnEndpoint(t *testing.T) {
	err := run(t.Context(), []string{"-iam=grpc", "-ops-addr="})
	if err == nil || !strings.Contains(err.Error(), "-iam-endpoint") {
		t.Fatalf("err %v", err)
	}
}

func TestStaticModeWarnsSignInDisabled(t *testing.T) {
	for _, tc := range []struct {
		mode, pwFile string
		want, not    []string
	}{
		{"static", "", []string{"level=WARN", "console sign-in disabled", "-console-token"}, []string{"root-password-file"}},
		{"static", "/run/secrets/pw", []string{"console sign-in disabled", "-root-password-file has no effect"}, nil},
		{"fake", "", nil, []string{"console sign-in disabled"}},
		{"grpc", "/run/secrets/pw", nil, []string{"console sign-in disabled", "no effect"}},
	} {
		var buf bytes.Buffer
		warnSignIn(t.Context(), slog.New(slog.NewTextHandler(&buf, nil)), tc.mode, tc.pwFile)
		for _, w := range tc.want {
			if !strings.Contains(buf.String(), w) {
				t.Errorf("%s %q: no %q in %q", tc.mode, tc.pwFile, w, buf.String())
			}
		}
		for _, w := range tc.not {
			if strings.Contains(buf.String(), w) {
				t.Errorf("%s %q: unexpected %q in %q", tc.mode, tc.pwFile, w, buf.String())
			}
		}
	}
}

func TestSignInEnabledOnlyWithRealIAM(t *testing.T) {
	for mode, want := range map[string]bool{"static": false, "fake": true, "grpc": true} {
		if got := signInEnabled(mode); got != want {
			t.Errorf("%s: %v", mode, got)
		}
	}
}
