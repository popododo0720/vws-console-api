package main

import (
	"bytes"
	"errors"
	"flag"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// clearCredentialEnv unsets every credential variable for the test.
func clearCredentialEnv(t *testing.T) {
	t.Helper()
	for _, c := range []credential{credConsoleToken(), credAccessKey(), credSecret()} {
		for _, name := range []string{c.env, c.env + "_FILE"} {
			t.Setenv(name, "")
			if err := os.Unsetenv(name); err != nil {
				t.Fatal(err)
			}
		}
	}
}

type credCase struct {
	args []string
	env  map[string]string
}

// resolve parses args into the three credential flags and resolves them with env.
func (c credCase) resolve(t *testing.T) (tok, ak, sk string, defaulted []credential, log string, err error) {
	t.Helper()
	fset := flag.NewFlagSet("t", flag.ContinueOnError)
	tokP := fset.String("console-token", "dev-token", "")
	akP := fset.String("access-key", "AKIDEXAMPLE", "")
	skP := fset.String("secret", "secret", "")
	if perr := fset.Parse(c.args); perr != nil {
		t.Fatal(perr)
	}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	env := credentialEnv{
		lookup:   func(k string) (string, bool) { v, ok := c.env[k]; return v, ok },
		readFile: os.ReadFile,
	}
	defaulted, err = resolveCredentials(t.Context(), fset, env, logger, tokP, akP, skP)
	return *tokP, *akP, *skP, defaulted, buf.String(), err
}

func writeFile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "cred")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCredentialsFromEnv(t *testing.T) {
	tok, ak, sk, defaulted, log, err := credCase{env: map[string]string{
		"VWS_CONSOLE_TOKEN": "tok-env-value", "VWS_ACCESS_KEY": "AKIDENV", "VWS_SECRET_KEY": "sk-env-value",
	}}.resolve(t)
	if err != nil {
		t.Fatal(err)
	}
	if tok != "tok-env-value" || ak != "AKIDENV" || sk != "sk-env-value" || len(defaulted) != 0 {
		t.Fatalf("got %q %q defaulted=%v", tok, ak, defaulted)
	}
	if log != "" {
		t.Fatalf("env credentials logged something: %q", log)
	}
}

func TestCredentialsFromFile(t *testing.T) {
	sk := writeFile(t, "sk-file-value\n")
	_, _, got, defaulted, _, err := credCase{env: map[string]string{"VWS_SECRET_KEY_FILE": sk}}.resolve(t)
	if err != nil {
		t.Fatal(err)
	}
	if got != "sk-file-value" {
		t.Fatalf("trailing newline not dropped or wrong value: %q", got)
	}
	if len(defaulted) != 2 || defaulted[0] != credConsoleToken() || defaulted[1] != credAccessKey() {
		t.Fatalf("defaulted %v", defaulted)
	}
}

func TestCredentialsDefaultsWhenUnset(t *testing.T) {
	tok, ak, sk, defaulted, _, err := credCase{}.resolve(t)
	if err != nil || tok != "dev-token" || ak != "AKIDEXAMPLE" || sk != "secret" || len(defaulted) != 3 {
		t.Fatalf("got %q %q %q %v %v", tok, ak, sk, defaulted, err)
	}
}

func TestCredentialFlagWinsAndWarnsWithoutTheValue(t *testing.T) {
	const flagValue = "sk-flag-value-must-not-be-logged"
	sk := writeFile(t, "sk-file-value\n")
	_, _, got, _, log, err := credCase{
		args: []string{"-secret=" + flagValue},
		env:  map[string]string{"VWS_SECRET_KEY_FILE": sk},
	}.resolve(t)
	if err != nil {
		t.Fatal(err)
	}
	if got != flagValue {
		t.Fatalf("flag did not take precedence over the file: %q", got)
	}
	if !strings.Contains(log, "level=WARN") || !strings.Contains(log, "deprecated credential flag") || !strings.Contains(log, "flag=-secret") {
		t.Fatalf("no deprecation warning naming the flag: %q", log)
	}
	if strings.Contains(log, flagValue) || strings.Contains(log, "sk-file-value") {
		t.Fatalf("the log carries a credential value: %q", log)
	}
}

func TestCredentialFilePrecedesEnvOnlyWhenAloneElseError(t *testing.T) {
	sk := writeFile(t, "sk-file-value")
	_, _, _, _, _, err := credCase{env: map[string]string{"VWS_SECRET_KEY_FILE": sk, "VWS_SECRET_KEY": "sk-env-value"}}.resolve(t)
	if err == nil || !strings.Contains(err.Error(), "VWS_SECRET_KEY_FILE and VWS_SECRET_KEY are both set") {
		t.Fatalf("err %v", err)
	}
	if strings.Contains(err.Error(), "sk-env-value") || strings.Contains(err.Error(), "sk-file-value") {
		t.Fatalf("the error carries a credential value: %v", err)
	}
}

func TestCredentialFileErrors(t *testing.T) {
	empty := writeFile(t, "\n")
	_, _, _, _, _, err := credCase{env: map[string]string{"VWS_CONSOLE_TOKEN_FILE": empty}}.resolve(t)
	if !errors.Is(err, errEmptyCredential) {
		t.Fatalf("empty file: err %v", err)
	}
	_, _, _, _, _, err = credCase{env: map[string]string{"VWS_ACCESS_KEY_FILE": filepath.Join(t.TempDir(), "missing")}}.resolve(t)
	if !errors.Is(err, fs.ErrNotExist) || !strings.Contains(err.Error(), "VWS_ACCESS_KEY_FILE") {
		t.Fatalf("missing file: err %v", err)
	}
}

func TestGRPCAcceptsCredentialsFromEnvAndFile(t *testing.T) {
	clearCredentialEnv(t)
	t.Setenv("VWS_CONSOLE_TOKEN", "tok-env-value")
	t.Setenv("VWS_ACCESS_KEY", "AKIDREAL")
	t.Setenv("VWS_SECRET_KEY_FILE", writeFile(t, "sk-file-value\n"))
	// The credential check passes, so run fails later on the next missing piece, not on credentials.
	err := run(t.Context(), []string{"-backend=grpc", "-iam=bogus", "-ops-addr="})
	if err == nil || strings.Contains(err.Error(), "development credentials") {
		t.Fatalf("err %v", err)
	}
}
