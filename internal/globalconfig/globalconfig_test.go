package globalconfig

import (
	"errors"
	"strings"
	"testing"
)

const valid = `
iam:
  etcd_endpoints: [https://10.0.0.1:2379, https://10.0.0.2:2379]
  tls:
    ca_file: /etc/vws/etcd-ca.pem
    cert_file: /run/credentials/vws-console-api/etcd.crt
    key_file: /run/credentials/vws-console-api/etcd.key
listeners:
  console: ":8080"
  ec2: 0.0.0.0:8081
  ops: 127.0.0.1:9090
credentials:
  kek_file: /run/credentials/vws-console-api/admin-kek
  mtls:
    ca_file: /etc/vws/internal-ca.pem
    cert_file: /run/credentials/vws-console-api/mtls.crt
    key_file: /run/credentials/vws-console-api/mtls.key
default_project: default
`

func TestParseTakesTheBootstrapKeys(t *testing.T) {
	cfg, err := Parse([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.IAM.EtcdEndpoints) != 2 || cfg.IAM.TLS.KeyFile != "/run/credentials/vws-console-api/etcd.key" ||
		cfg.Listeners.Console != ":8080" || cfg.Listeners.S3 != "" ||
		cfg.Credentials.KEKFile != "/run/credentials/vws-console-api/admin-kek" ||
		cfg.Credentials.MTLS.CAFile != "/etc/vws/internal-ca.pem" || cfg.DefaultProject != "default" {
		t.Fatalf("got %+v", cfg)
	}
}

// TestParseRefusesWhatIsNotBootstrap is #734: global.yaml holds only the
// bootstrap keys. A region or account entry belongs to the admin API, a
// secret is named by file, and anything else unknown or ambiguous is
// refused rather than ignored.
func TestParseRefusesWhatIsNotBootstrap(t *testing.T) {
	with := func(old, repl string) string {
		if !strings.Contains(valid, old) {
			t.Fatalf("fixture has no %q", old)
		}
		return strings.Replace(valid, old, repl, 1)
	}
	const mtlsKey = "key_file: /run/credentials/vws-console-api/mtls.key"
	const kekFile = "kek_file: /run/credentials/vws-console-api/admin-kek"
	pem := "|\n      -----BEGIN PRIVATE KEY-----\n      MIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n      -----END PRIVATE KEY-----"
	for _, tc := range []struct {
		name string
		yaml string
		want error
	}{
		{"regions", valid + "regions:\n  - name: pve-seoul-1\n    pve_api_url: https://10.0.0.5:8006\n", ErrRegistration},
		{"one region", valid + "region: vws-1\n", ErrRegistration},
		{"aws accounts", valid + "aws_accounts:\n  - aws_account_id: \"123456789012\"\n", ErrRegistration},
		{"capitalized registration", valid + "Regions: []\n", ErrRegistration},
		{"token secret", valid + "token_secret: abc123\n", ErrInlineSecret},
		{"inline kek", with("kek_file: /run/credentials/vws-console-api/admin-kek", "kek: q83vEjRWeJA="), ErrInlineSecret},
		{"inline tls key", with("key_file: /run/credentials/vws-console-api/etcd.key", "key: "+pem), ErrInlineSecret},
		{"pem in a file field", with(mtlsKey, "key_file: "+pem), ErrInlineSecret},
		{"kek value in a file field", with(kekFile, "kek_file: q83vEjRWeJA="), ErrInlineSecret},
		{"relative file", with("ca_file: /etc/vws/etcd-ca.pem", "ca_file: etcd-ca.pem"), ErrInlineSecret},
		{"etcd password in url", with("https://10.0.0.1:2379", "https://root:hunter2@10.0.0.1:2379"), ErrInlineSecret},
		{"etcd password key", with("  etcd_endpoints:", "  etcd_password: hunter2\n  etcd_endpoints:"), ErrInlineSecret},
		{"unknown key", valid + "log_level: debug\n", ErrInvalid},
		{"unknown nested key", with("  ops: 127.0.0.1:9090", "  ops: 127.0.0.1:9090\n  admin: :9443"), ErrInvalid},
		{"duplicate key", valid + "default_project: other\n", ErrInvalid},
		{"two documents", valid + "---\ndefault_project: other\n", ErrInvalid},
		{"empty", "", ErrInvalid},
		{"not a mapping", "- a\n- b\n", ErrInvalid},
		{"plaintext etcd", with("https://10.0.0.1:2379", "http://10.0.0.1:2379"), ErrInvalid},
		{"etcd without port", with("https://10.0.0.1:2379", "https://10.0.0.1"), ErrInvalid},
		{"no etcd", with("  etcd_endpoints: [https://10.0.0.1:2379, https://10.0.0.2:2379]\n", ""), ErrInvalid},
		{"no ca", with("    ca_file: /etc/vws/etcd-ca.pem\n", ""), ErrInvalid},
		{"no kek", with("  kek_file: /run/credentials/vws-console-api/admin-kek\n", ""), ErrInvalid},
		{"cert without key", with("    key_file: /run/credentials/vws-console-api/mtls.key\n", ""), ErrInvalid},
		{"bad listener", with(`console: ":8080"`, "console: localhost"), ErrInvalid},
		{"listener port out of range", with(`console: ":8080"`, `console: ":70000"`), ErrInvalid},
		{"no default project", with("default_project: default\n", ""), ErrInvalid},
		{"default project with a space", with("default_project: default", "default_project: a b"), ErrInvalid},
		{"oversized", valid + "#" + strings.Repeat("x", MaxBytes) + "\n", ErrInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.yaml))
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			for _, other := range []error{ErrRegistration, ErrInlineSecret, ErrInvalid} {
				if errors.Is(err, other) && !errors.Is(tc.want, other) {
					t.Fatalf("got %v, which is also %v", err, other)
				}
			}
			for _, secret := range []string{"hunter2", "q83vEjRWeJA", "MIIEvQ", "abc123"} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("error %q repeats the secret", err)
				}
			}
		})
	}
}
