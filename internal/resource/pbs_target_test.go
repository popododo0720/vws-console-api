package resource

import "testing"

func TestParsePBSRepository(t *testing.T) {
	for in, want := range map[string]PBSRepository{
		"pbs.example:dr-store":        {Address: "pbs.example:8007", Datastore: "dr-store"},
		"pbs.example:8443:dr-store":   {Address: "pbs.example:8443", Datastore: "dr-store"},
		"192.0.2.7:dr_1":              {Address: "192.0.2.7:8007", Datastore: "dr_1"},
		"[2001:db8::7]:dr-store":      {Address: "[2001:db8::7]:8007", Datastore: "dr-store"},
		"[2001:db8::7]:9000:dr-store": {Address: "[2001:db8::7]:9000", Datastore: "dr-store"},
	} {
		got, err := ParsePBSRepository(in)
		if err != nil || got != want {
			t.Errorf("%q: %+v %v, want %+v", in, got, err, want)
		}
	}
	for _, in := range []string{
		"", "dr-store", ":dr-store", "pbs.example:", "pbs.example:ab", "root@pam@pbs.example:dr-store",
		"2001:db8::7:dr-store", "[2001:db8::7:dr-store", "[192.0.2.7]:dr-store", "pbs.example:0:dr-store",
		"pbs.example:65536:dr-store", "pbs.example:08007:dr-store", "pbs..example:dr-store", "pbs/x:dr-store",
		"pbs.example:dr/store",
	} {
		if _, err := ParsePBSRepository(in); err == nil || AsError(err).Field != "pbsRepository" {
			t.Errorf("%q accepted: %v", in, err)
		}
	}
}

func TestCheckPBSTarget(t *testing.T) {
	fp := "ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89"
	if err := CheckPBSTarget("", "", "", ""); err != nil {
		t.Fatalf("a region without DR: %v", err)
	}
	if err := CheckPBSTarget("pbs.example:dr-store", "vws/pve-test-1", fp, "dr@pbs!export"); err != nil {
		t.Fatalf("valid target: %v", err)
	}
	for _, tc := range []struct{ repository, namespace, fingerprint, tokenID, field string }{
		{"", "vws", fp, "dr@pbs!export", "pbsRepository"},
		{"pbs.example:dr-store", "", fp, "dr@pbs!export", "pbsNamespace"},
		{"pbs.example:dr-store", "a/b/c/d/e/f/g/h", fp, "dr@pbs!export", "pbsNamespace"},
		{"pbs.example:dr-store", "vws//x", fp, "dr@pbs!export", "pbsNamespace"},
		{"pbs.example:dr-store", "../x", fp, "dr@pbs!export", "pbsNamespace"},
		{"pbs.example:dr-store", "vws", "", "dr@pbs!export", "pbsFingerprint"},
		{"pbs.example:dr-store", "vws", "AB" + fp[2:], "dr@pbs!export", "pbsFingerprint"},
		{"pbs.example:dr-store", "vws", fp, "", "pbsTokenId"},
		{"pbs.example:dr-store", "vws", fp, "dr@pbs", "pbsTokenId"},
	} {
		err := CheckPBSTarget(tc.repository, tc.namespace, tc.fingerprint, tc.tokenID)
		if err == nil || AsError(err).Field != tc.field {
			t.Errorf("%+v: %v, want field %s", tc, err, tc.field)
		}
	}
}
