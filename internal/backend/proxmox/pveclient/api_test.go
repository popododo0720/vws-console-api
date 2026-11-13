package pveclient

import (
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestVMConfigPVE92Representative(t *testing.T) {
	data, err := os.ReadFile("testdata/pve-9.2-representative-config.json")
	if err != nil {
		t.Fatal(err)
	}
	var cfg VMConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Name != "web-1" || cfg.Memory != 1024 || cfg.Cores != 1 || cfg.Sockets != 1 ||
		cfg.Agent != "1" || cfg.Balloon != 512 || cfg.Template != 0 || cfg.Protection != 0 ||
		cfg.Digest != "0de0e2713135348a2ba880cc161ee96672c5234a" ||
		cfg.SMBIOS1 != "uuid=5f0c3e9a-8b5d-4b8e-9a51-0c2d6c1f7a10" ||
		cfg.Drives["scsi0"] != "local-lvm:vm-100-disk-0,size=8G" {
		t.Fatalf("config = %+v", cfg)
	}
}

func TestVMConfigNumericForms(t *testing.T) {
	for _, field := range []string{"memory", "cores", "sockets", "balloon", "template", "protection"} {
		for _, value := range []string{`1024`, `"1024"`, `0`, `"0"`, `""`, `null`} {
			t.Run(field+"/"+value, func(t *testing.T) {
				cfg := VMConfig{Memory: 99, Agent: "stale"}
				if err := json.Unmarshal([]byte(`{"`+field+`":`+value+`}`), &cfg); err != nil {
					t.Fatal(err)
				}
				got := map[string]int{
					"memory": cfg.Memory, "cores": cfg.Cores, "sockets": cfg.Sockets,
					"balloon": cfg.Balloon, "template": cfg.Template, "protection": cfg.Protection,
				}[field]
				want := 0
				if strings.Contains(value, "1024") {
					want = 1024
				}
				if got != want || cfg.Agent != "" {
					t.Fatalf("config = %+v, want %s=%d", cfg, field, want)
				}
			})
		}
		for _, value := range []string{`"bad"`, `"1.5"`, `1.5`, `true`, `{}`, `[]`, `"999999999999999999999999"`} {
			var cfg VMConfig
			err := json.Unmarshal([]byte(`{"`+field+`":`+value+`}`), &cfg)
			if err == nil || !strings.Contains(err.Error(), "pveclient: VM config:") {
				t.Fatalf("%s=%s: %v", field, value, err)
			}
			if value == `"bad"` {
				var numberErr *strconv.NumError
				if !errors.As(err, &numberErr) {
					t.Fatalf("numeric cause not wrapped: %v", err)
				}
			}
		}
	}
	var cfg VMConfig
	if err := json.Unmarshal([]byte(`{}`), &cfg); err != nil || cfg.Memory != 0 {
		t.Fatalf("missing fields = %+v, %v", cfg, err)
	}
}

func TestVMConfigAgentForms(t *testing.T) {
	for _, value := range []string{`1`, `"1"`, `"enabled=1,fstrim_cloned_disks=1"`, `""`, `0`, `"0"`} {
		var cfg VMConfig
		if err := json.Unmarshal([]byte(`{"agent":`+value+`}`), &cfg); err != nil {
			t.Fatal(err)
		}
		if cfg.Agent != strings.Trim(value, `"`) {
			t.Fatalf("agent = %q, input %s", cfg.Agent, value)
		}
	}
	for _, value := range []string{`true`, `1.5`, `{}`, `[]`} {
		var cfg VMConfig
		if err := json.Unmarshal([]byte(`{"agent":`+value+`}`), &cfg); err == nil {
			t.Fatalf("accepted agent %s", value)
		}
	}
}
