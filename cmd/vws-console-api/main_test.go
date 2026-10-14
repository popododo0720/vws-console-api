package main

import (
	"os"
	"strings"
	"syscall"
	"testing"
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
