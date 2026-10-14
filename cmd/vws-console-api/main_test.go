package main

import (
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
	err := run(t.Context(), []string{"-backend=grpc", "-access-key=AKIDREAL"})
	if err == nil {
		t.Fatal("grpc backend started with the default console token and secret")
	}
	for _, want := range []string{"-console-token", "-secret"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %s", err, want)
		}
	}
	if strings.Contains(err.Error(), "-access-key") {
		t.Errorf("error %q names a flag that was given", err)
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
	if err := setRootPassword(root, good); err != nil {
		t.Fatal(err)
	}
	if _, err := root.Login(t.Context(), iam.LoginRequest{Account: account, UserName: iam.RootUserName, Password: "root password 9"}); err != nil {
		t.Errorf("the trailing newline was not dropped: %v", err)
	}
}
