package proxmox

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/regionhelper"
)

func TestTokenDeleteSerializesRegistration(t *testing.T) {
	dir := t.TempDir()
	source, err := filepath.Abs("../../../internal/regionhelper/helper.go")
	if err != nil {
		t.Fatal(err)
	}
	code, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	// The overlay controls scheduling without adding a production test hook.
	const anchor = "\tif err := confined(root, filepath.Join(root, name)); err != nil {"
	const pause = `
	if args[0] == "token-delete" && os.Getenv("VWS_HELPER_TEST_DELETE_GATE") != "" {
		gate := os.Getenv("VWS_HELPER_TEST_DELETE_GATE")
		checked, err := os.OpenFile(gate+"/checked", os.O_WRONLY, 0)
		if err != nil { return err }
		_, writeErr := checked.Write([]byte{1})
		if err := errors.Join(writeErr, checked.Close()); err != nil { return err }
		resume, err := os.Open(gate+"/resume")
		if err != nil { return err }
		_, readErr := io.ReadFull(resume, make([]byte, 1))
		if err := errors.Join(readErr, resume.Close()); err != nil { return err }
	}
`
	if strings.Count(string(code), anchor) != 1 {
		t.Fatal("cannot place scheduling barrier after the identity check")
	}
	replacement := filepath.Join(dir, "helper.go")
	writeFixture(t, replacement, []byte(strings.Replace(string(code), anchor, pause+anchor, 1)))
	overlay, err := json.Marshal(map[string]any{"Replace": map[string]string{source: replacement}})
	if err != nil {
		t.Fatal(err)
	}
	overlayPath := filepath.Join(dir, "overlay.json")
	writeFixture(t, overlayPath, overlay)
	binary := filepath.Join(dir, "helper")
	build := exec.CommandContext(t.Context(), "go", "test", "-c", "-overlay", overlayPath,
		"-o", binary, "./internal/regionhelper")
	build.Dir = "../../.."
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build helper: %v\n%s", err, out)
	}
	for _, name := range []string{
		"etc/pve/vws", "etc/pve/priv/vws", "etc/pve/priv/lock/vws-region", "etc/vws/credentials",
	} {
		if err := os.MkdirAll(filepath.Join(dir, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"checked", "resume"} {
		if err := syscall.Mkfifo(filepath.Join(dir, name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	checked, err := os.OpenFile(filepath.Join(dir, "checked"), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer checked.Close()
	resume, err := os.OpenFile(filepath.Join(dir, "resume"), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer resume.Close()
	writeFixture(t, filepath.Join(dir, "etc/vws/credentials/region-kek"), []byte(strings.Repeat("*", 32)))
	t.Setenv("VWS_HELPER_TEST_ROOT", dir)
	client := regionhelper.Client{Path: binary}
	oldFP, newFP := tokenFingerprint("gate-old-secret"), tokenFingerprint("gate-new-secret")
	for secret, fp := range map[string]string{"gate-old-secret": oldFP, "gate-new-secret": newFP} {
		if err := client.WriteToken(t.Context(), fp, []byte(secret)); err != nil {
			t.Fatal(err)
		}
	}
	identity := func(fp string) []byte { return []byte(`{"fingerprint":"` + fp + `"}`) }
	if err := client.WriteRegistration(t.Context(), identity(oldFP)); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VWS_HELPER_TEST_DELETE_GATE", dir)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- client.DeleteToken(ctx, newFP) }()
	barrier := make(chan error, 1)
	go func() { _, err := io.ReadFull(checked, make([]byte, 1)); barrier <- err }()
	select {
	case err := <-barrier:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("delete did not reach the identity-check barrier")
	}
	writerErr := client.Lock(t.Context(), "registration")
	if writerErr == nil {
		if err := client.WriteToken(t.Context(), newFP, []byte("gate-new-secret")); err != nil {
			t.Fatal(err)
		}
		if err := client.WriteRegistration(t.Context(), identity(newFP)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := resume.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	deleteErr := <-done
	t.Setenv("VWS_HELPER_TEST_DELETE_GATE", "")
	if writerErr != nil {
		if err := client.Lock(t.Context(), "registration"); err != nil {
			t.Fatal(err)
		}
		if err := client.WriteToken(t.Context(), newFP, []byte("gate-new-secret")); err != nil {
			t.Fatal(err)
		}
		if err := client.WriteRegistration(t.Context(), identity(newFP)); err != nil {
			t.Fatal(err)
		}
	}
	if err := client.Unlock(t.Context(), "registration"); err != nil {
		t.Fatal(err)
	}
	_, statErr := os.Stat(filepath.Join(dir, "etc/pve/priv/vws", "pve-token."+newFP))
	t.Logf("deleteErr=%v writerEntered=%v activeTokenMissing=%v", deleteErr, writerErr == nil, os.IsNotExist(statErr))
	if statErr != nil || writerErr == nil || deleteErr != nil {
		t.Fatal("token deletion did not serialize with registration publication")
	}
	t.Run("busy_lock", func(t *testing.T) {
		if err := client.Lock(t.Context(), "registration"); err != nil {
			t.Fatal(err)
		}
		defer client.Unlock(t.Context(), "registration")
		if err := client.DeleteToken(t.Context(), oldFP); err == nil {
			t.Fatal("delete accepted a held registration lock")
		}
		if _, err := os.Stat(filepath.Join(dir, "etc/pve/priv/vws", "pve-token."+oldFP)); err != nil {
			t.Fatal("busy delete removed the token:", err)
		}
		if _, err := os.Stat(filepath.Join(dir, "etc/pve/priv/lock/vws-region", "registration")); err != nil {
			t.Fatal("busy delete removed the writer's lock:", err)
		}
	})
	for _, fp := range []string{newFP, oldFP} {
		err := client.DeleteToken(t.Context(), fp)
		if (err == nil) != (fp == oldFP) {
			t.Fatalf("delete active=%v: %v", fp == newFP, err)
		}
		if _, err := os.Stat(filepath.Join(dir, "etc/pve/priv/lock/vws-region", "registration")); !os.IsNotExist(err) {
			t.Fatal("delete left the registration lock:", err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "etc/pve/priv/vws", "pve-token."+oldFP)); !os.IsNotExist(err) {
		t.Fatal("inactive token remains:", err)
	}
}
