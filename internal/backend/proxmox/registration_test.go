package proxmox

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
)

func registrationZones(count int) []backend.Zone {
	zones := make([]backend.Zone, (count+249)/250)
	for i := range zones {
		zones[i].Letter = string(rune('a' + i))
	}
	for i := range count {
		zones[i/250].Nodes = append(zones[i/250].Nodes, fmt.Sprintf("n%062d", i))
	}
	return zones
}

func TestUnregisteredConnection(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "region.yaml")
	writeFixture(t, config, []byte("read_only: true\n"))
	conn, err := Open(config, filepath.Join(dir, "registration.json"), "https://unused", nil)
	if err != nil {
		t.Fatalf("unregistered daemon cannot start: %v", err)
	}
	if _, err := conn.Check(t.Context()); err == nil || err.Error() != "unregistered" {
		t.Fatalf("readiness reason = %v, want unregistered", err)
	}
}

func TestRegistrationRejectsInvalidInput(t *testing.T) {
	good := `{"region":"pve-test-1","cluster_name":"test","tokenId":"vws@pve!inventory","token":"fake-secret"}`
	for _, bad := range []string{
		`null`, `{}`, good + `{}`, strings.Replace(good, `"region"`, `"unknown"`, 1),
		strings.Replace(good, `"test"`, `"a/b"`, 1),
		strings.TrimSuffix(good, "}") + `,"zones":[{"letter":"A","nodes":[]}]}`,
		strings.TrimSuffix(good, "}") + `,"zones":[{"letter":"a","nodes":["n","n"]}]}`,
		strings.TrimSuffix(good, "}") + `,"zones":[{"letter":"a"},{"letter":"a"}]}`,
	} {
		if _, err := decodeRegistration([]byte(bad)); err == nil {
			t.Fatal("accepted invalid registration")
		}
	}
}
