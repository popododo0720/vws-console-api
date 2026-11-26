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

func TestCheckDRSettings(t *testing.T) {
	fp := "ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89"
	if err := CheckDRSettings(DRSettings{}); err != nil {
		t.Fatalf("a region without DR: %v", err)
	}
	valid := DRSettings{
		Storage: "dr-pbs", Repository: "pbs.example:dr-store", Namespace: "vws/pve-test-1",
		Fingerprint: fp, TokenID: "dr@pbs!export",
	}
	if err := CheckDRSettings(valid); err != nil {
		t.Fatalf("valid settings: %v", err)
	}
	for field, edit := range map[string][]func(*DRSettings){
		"drStorage": {
			func(d *DRSettings) { d.Storage = "" }, func(d *DRSettings) { d.Storage = "Dr" },
			func(d *DRSettings) { d.Storage = "dr/x" },
		},
		"pbsRepository": {func(d *DRSettings) { d.Repository = "" }},
		"pbsNamespace": {
			func(d *DRSettings) { d.Namespace = "" }, func(d *DRSettings) { d.Namespace = "a/b/c/d/e/f/g/h" },
			func(d *DRSettings) { d.Namespace = "vws//x" }, func(d *DRSettings) { d.Namespace = "../x" },
		},
		"pbsFingerprint": {
			func(d *DRSettings) { d.Fingerprint = "" }, func(d *DRSettings) { d.Fingerprint = "AB" + fp[2:] },
		},
		"pbsTokenId": {func(d *DRSettings) { d.TokenID = "" }, func(d *DRSettings) { d.TokenID = "dr@pbs" }},
	} {
		for i, change := range edit {
			d := valid
			change(&d)
			if err := CheckDRSettings(d); err == nil || AsError(err).Field != field {
				t.Errorf("%s case %d: %v", field, i, err)
			}
		}
	}
}
