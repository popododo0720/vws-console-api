package resource

import "testing"

func TestValidPVEConnectionSteps(t *testing.T) {
	step := func(name string, result ConnectionResult, message string) ConnectionStep {
		return ConnectionStep{Name: name, Result: result, Message: message}
	}
	pass := []ConnectionStep{
		step("tls", ConnectionPass, "PVE TLS certificate verified"),
		step("version", ConnectionPass, "PVE version read succeeded"),
		step("cluster_name", ConnectionPass, "cluster_name accepted"),
		step("privileges", ConnectionPass, "token privileges are read-only"),
	}
	with := func(i int, s ConnectionStep) []ConnectionStep {
		out := append([]ConnectionStep(nil), pass...)
		out[i] = s
		return out
	}
	skipped := step("privileges", ConnectionSkipped, "previous step failed")
	for _, tc := range []struct {
		name  string
		steps []ConnectionStep
		ok    bool
	}{
		{"all pass", pass, true},
		{"tls fails", []ConnectionStep{
			step("tls", ConnectionFail, "PVE TLS handshake failed"),
			step("version", ConnectionSkipped, "previous step failed"),
			step("cluster_name", ConnectionSkipped, "previous step failed"), skipped,
		}, true},
		{"pool is missing a privilege", with(3, step("privileges", ConnectionFail,
			`pool "mapped": missing Pool.Audit`)), true},
		{"write privilege", with(3, step("privileges", ConnectionFail,
			"token holds a privilege outside PVEAuditor read-only access")), true},
		{"free text", with(3, step("privileges", ConnectionFail, "PVE said: secret")), false},
		{"pool text with another tail", with(3, step("privileges", ConnectionFail,
			`pool "a": missing Pool.Audit: secret`)), false},
		{"pool text on another step", with(0, step("tls", ConnectionFail, `pool "a": missing Pool.Audit`)), false},
		{"pass message of another step", with(1, step("version", ConnectionPass, "cluster_name accepted")), false},
		{"unknown result", with(1, step("version", "MAYBE", "PVE version read succeeded")), false},
		{"pass after a failure", []ConnectionStep{
			step("tls", ConnectionFail, "PVE TLS handshake failed"), pass[1], pass[2], pass[3],
		}, false},
		{"skip with no failure", with(3, skipped), false},
		{"wrong order", []ConnectionStep{pass[1], pass[0], pass[2], pass[3]}, false},
		{"three steps", pass[:3], false},
		{"five steps", append(append([]ConnectionStep(nil), pass...), step("regionapi", ConnectionPass, "x")), false},
		{"none", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ValidPVEConnectionSteps(tc.steps); got != tc.ok {
				t.Fatalf("ValidPVEConnectionSteps = %v, want %v", got, tc.ok)
			}
		})
	}
}
