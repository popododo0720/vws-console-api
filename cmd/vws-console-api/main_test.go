package main

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestAdminAuditFileIsSeparate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	app := &syncBuffer{}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(app, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	t.Cleanup(func() {
		data, err := os.ReadFile(path)
		const warning = `"level":"WARN","msg":"in-memory admin registry: registrations are lost on restart"`
		if err != nil || strings.Count(string(data), `"action":"AdminRegisterAwsAccount"`) != 1 ||
			!strings.Contains(app.String(), warning) ||
			strings.Contains(app.String(), "AdminRegisterAwsAccount") {
			t.Errorf("audit stream separation failed: %v", err)
		}
	})
	p := startFakeProcess(t, "-audit-log="+path, "-admin-store=memory")
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		"http://"+p.console+"/api/v1/admin/aws-accounts", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer dev-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("write without KEK: %d", resp.StatusCode)
	}
}

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

func TestRegistryConfiguration(t *testing.T) {
	g, key, closeRegistry, err := openRegistry(t.Context(), "", "fake")
	if err != nil {
		t.Fatal(err)
	}
	if key != nil {
		t.Fatal("fake mode unexpectedly loaded a KEK")
	}
	t.Cleanup(func() {
		if err := closeRegistry(); err != nil {
			t.Error(err)
		}
	})
	if _, _, err := g.Regions().List(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := openRegistry(t.Context(), "", "grpc"); err == nil {
		t.Fatal("production silently used memory")
	}
	if _, _, _, err := openRegistry(t.Context(), filepath.Join(t.TempDir(), "missing"), "fake"); err == nil {
		t.Fatal("missing bootstrap file accepted")
	}
	path := filepath.Join(t.TempDir(), "global.yaml")
	if err := os.WriteFile(path, []byte("unknown: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := openRegistry(t.Context(), path, "fake"); err == nil {
		t.Fatal("invalid bootstrap accepted")
	}
}

func TestAdminBootstrapRejectsInvalidFlags(t *testing.T) {
	invalidKEK := writeFile(t, "invalid")
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"-admin-store=disk"}, `unknown -admin-store "disk"`},
		{[]string{"-admin-store=memory", "-global-config=x"}, "-admin-store memory conflicts with -global-config"},
		{[]string{"-admin-kek-file=x"}, "-admin-kek-file requires -admin-store memory"},
		{[]string{"-global-config=x", "-admin-kek-file=x"}, "-admin-kek-file requires -admin-store memory"},
		{[]string{"-admin-store=memory", "-admin-kek-file=/missing/kek"}, "load -admin-kek-file"},
		{[]string{"-admin-store=memory", "-admin-kek-file=" + invalidKEK}, "load -admin-kek-file"},
		{[]string{"-region-mtls-ca-file=x"}, "require all three files"},
		{[]string{"-region-mtls-cert-file=x"}, "require all three files"},
		{[]string{"-region-mtls-key-file=x"}, "require all three files"},
		{[]string{"-region-mtls-ca-file=x", "-region-mtls-cert-file=x"}, "require all three files"},
		{[]string{"-region-mtls-ca-file=x", "-region-mtls-key-file=x"}, "require all three files"},
		{[]string{"-region-mtls-cert-file=x", "-region-mtls-key-file=x"}, "require all three files"},
		{
			[]string{"-global-config=x", "-region-mtls-ca-file=x", "-region-mtls-cert-file=x", "-region-mtls-key-file=x"},
			"-region-mtls-* conflicts with -global-config",
		},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			err := run(ctx, tc.args)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err %v, want %q", err, tc.want)
			}
		})
	}
}

func TestAdminMemoryRegistryForEveryBackend(t *testing.T) {
	for _, kind := range []string{"fake", "proxmox", "grpc", "regions"} {
		t.Run(kind, func(t *testing.T) {
			g, key, closeRegistry, err := (adminBootstrap{store: "memory"}).open(t.Context(), "", kind)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := closeRegistry(); err != nil {
					t.Error(err)
				}
			}()
			items, _, err := g.Regions().List(t.Context())
			if err != nil || len(items) != 0 || key != nil {
				t.Fatalf("memory registry without KEK: %v %v %v", items, key, err)
			}
		})
	}
}

func TestRegionsDefaultStillRequiresGlobalConfig(t *testing.T) {
	clearCredentialEnv(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	err := run(ctx, []string{
		"-backend=regions", "-console-token=token", "-access-key=key", "-secret=value",
	})
	const want = "-global-config is required for the admin registry with -backend=regions"
	if err == nil || err.Error() != want {
		t.Fatalf("default registry error: %v, want %q", err, want)
	}
}

func TestAWSProxySocketConfiguration(t *testing.T) {
	clearCredentialEnv(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, path := range []string{
		"", "/", "relative.sock", "/run/vws/../proxy.sock", "/run//proxy.sock", "/" + strings.Repeat("x", 107),
	} {
		err := run(ctx, []string{
			"-aws-proxy-socket=" + path,
			"-console-addr=127.0.0.1:0", "-ec2-addr=127.0.0.1:0", "-s3-addr=127.0.0.1:0", "-iam-addr=127.0.0.1:0", "-ops-addr=",
		})
		if err == nil || !strings.Contains(err.Error(), "socket") {
			t.Fatalf("invalid socket accepted: %q: %v", path, err)
		}
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

func TestGRPCIAMIgnoresLocalRootPasswordFile(t *testing.T) {
	err := run(t.Context(), []string{
		"-iam=grpc", "-root-password-file=" + filepath.Join(t.TempDir(), "absent"), "-ops-addr=",
	})
	if err == nil || !strings.Contains(err.Error(), "-iam-endpoint") {
		t.Fatalf("grpc tried to read the local password file: %v", err)
	}
}

// A bad -iam-tls-* setting stops the process at start instead of dialing
// vws-iam in plaintext.
func TestGRPCIAMRejectsBadTLSFlags(t *testing.T) {
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"missing CA file": {[]string{"-iam-tls-ca-file=" + filepath.Join(t.TempDir(), "absent.crt")}, "read vws-iam CA file"},
		"cert without CA": {[]string{"-iam-tls-cert-file=/x.crt", "-iam-tls-key-file=/x.key"}, "needs a CA file"},
	} {
		t.Run(name, func(t *testing.T) {
			args := append([]string{"-iam=grpc", "-iam-endpoint=127.0.0.1:1", "-ops-addr="}, tc.args...)
			if err := run(t.Context(), args); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err %v, want %q", err, tc.want)
			}
		})
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
		{"grpc", "", nil, []string{"console sign-in disabled", "no effect"}},
		{
			"grpc", "/run/secrets/pw",
			[]string{"-root-password-file has no effect", "vws-iam owns console sign-in"},
			[]string{"console sign-in disabled"},
		},
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

// A sign-in limit flag outside its bounds stops the process at start.
func TestBadLoginLimitsAreRejected(t *testing.T) {
	for _, flag := range []string{
		"-login-ip-burst=0", "-login-user-burst=10001", "-login-ip-refill=1ms",
		"-login-user-refill=48h", "-login-max-keys=5",
	} {
		err := run(t.Context(), []string{flag, "-ops-addr="})
		if err == nil || !strings.Contains(err.Error(), "-login-*") {
			t.Errorf("%s: err %v", flag, err)
		}
	}
}

func TestBadLaunchLimitsAreRejected(t *testing.T) {
	for _, flag := range []string{
		"-launch-inflight-per-account=9", "-launch-inflight-global=100001", "-launch-inflight-per-account=101",
		"-launch-queue=-1", "-launch-queue=100001", "-launch-queue-wait=-1s", "-launch-queue-wait=31s",
	} {
		err := run(t.Context(), []string{flag, "-ops-addr="})
		if err == nil || !strings.Contains(err.Error(), "-launch-*") {
			t.Errorf("%s: err %v", flag, err)
		}
	}
}

func TestBadRequestLimitsAreRejected(t *testing.T) {
	for _, flag := range []string{
		"-ec2-launch-burst=0", "-ec2-describe-burst=100001", "-ec2-mutate-rate=0",
		"-ec2-launch-rate=-1", "-ec2-describe-rate=NaN", "-ec2-limit-max-keys=5",
	} {
		err := run(t.Context(), []string{flag, "-ops-addr="})
		if err == nil || !strings.Contains(err.Error(), "-ec2-*") {
			t.Errorf("%s: err %v", flag, err)
		}
	}
}
