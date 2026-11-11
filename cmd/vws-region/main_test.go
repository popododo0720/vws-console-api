package main

import (
	"strings"
	"testing"
)

func TestTokenInputsAreRefused(t *testing.T) {
	const secret = "must-never-be-echoed"
	for _, args := range [][]string{
		{"-token=" + secret},
		{"-pve-token=" + secret},
		{"-secret=" + secret},
		{"-backend=fake"},
		{"unexpected"},
		{"-ec2-addr=:8081"},
		{"-s3-addr=:8082"},
		{"-console-addr=:8080"},
		{"-pve-endpoint=https://user:" + secret + "@localhost:8006"},
	} {
		if err := run(t.Context(), args); err == nil || strings.Contains(err.Error(), secret) {
			t.Fatalf("input not safely refused: %v", err)
		}
	}
	for _, name := range []string{"PVE_TOKEN", "PROXMOX_API_TOKEN", "VWS_PVE_TOKEN", "VWS_PVE_TOKEN_FILE"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, secret)
			if err := run(t.Context(), nil); err == nil || !strings.Contains(err.Error(), "environment") ||
				strings.Contains(err.Error(), secret) {
				t.Fatalf("environment not safely refused: %v", err)
			}
		})
	}
}
