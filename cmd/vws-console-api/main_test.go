package main

import (
	"os"
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
