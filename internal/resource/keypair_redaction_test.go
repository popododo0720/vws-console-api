package resource

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func TestKeyPairMaterialIsNeverFormattedOrLogged(t *testing.T) {
	const (
		material = "private-key-material-that-must-not-appear"
		marker   = "<redacted>"
	)

	id, err := Parse[KeyPairID]("key-01234567")
	if err != nil {
		t.Fatalf("parse key pair id: %v", err)
	}
	owner, err := Parse[AccountID]("123456789012")
	if err != nil {
		t.Fatalf("parse account id: %v", err)
	}
	kp := KeyPair{
		ID:          id,
		OwnerID:     owner,
		Name:        "web",
		Fingerprint: "aa:bb:cc",
		Material:    material,
		Type:        KeyTypeRSA,
	}

	for _, format := range []string{"%v", "%+v", "%#v"} {
		out := fmt.Sprintf(format, kp)
		if strings.Contains(out, material) {
			t.Fatalf("%s leaked the private key: %q", format, out)
		}
		if !strings.Contains(out, marker) {
			t.Fatalf("%s did not redact the material: %q", format, out)
		}
		if !strings.Contains(out, "key-01234567") || !strings.Contains(out, "web") {
			t.Fatalf("%s lost the key pair fields: %q", format, out)
		}
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	logger.InfoContext(t.Context(), "key pair", slog.Any("key_pair", kp))
	line := buf.String()
	if strings.Contains(line, material) {
		t.Fatalf("log leaked the private key: %s", line)
	}
	if !strings.Contains(line, marker) {
		t.Fatalf("log did not redact the material: %s", line)
	}
	var record map[string]any
	if err := json.Unmarshal(buf.Bytes(), &record); err != nil {
		t.Fatalf("log line is not JSON: %v", err)
	}
	group, ok := record["key_pair"].(map[string]any)
	if !ok {
		t.Fatalf("log has no key_pair group: %v", record["key_pair"])
	}
	if got := group["id"]; got != "key-01234567" {
		t.Fatalf("key_pair.id = %v, want key-01234567", got)
	}
	if got := group["material"]; got != marker {
		t.Fatalf("key_pair.material = %v, want %s", got, marker)
	}

	wire, err := json.Marshal(kp)
	if err != nil {
		t.Fatalf("marshal key pair: %v", err)
	}
	if !strings.Contains(string(wire), `"keyMaterial"`) || !strings.Contains(string(wire), material) {
		t.Fatalf("json wire lost keyMaterial: %s", wire)
	}
	var decoded KeyPair
	if err := json.Unmarshal(wire, &decoded); err != nil {
		t.Fatalf("unmarshal key pair: %v", err)
	}
	if decoded.Material != material {
		t.Fatalf("json wire dropped the private key: %s", wire)
	}
}
