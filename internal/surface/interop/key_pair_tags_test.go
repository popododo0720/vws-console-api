package interop

import (
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"maps"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
	"github.com/popododo0720/vws-console-api/internal/surface/console"
	"github.com/popododo0720/vws-console-api/internal/surface/ec2query"
)

func TestConsoleAndQueryKeyPairTagsMatch(t *testing.T) {
	now := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	account := mustParse[resource.AccountID](t, "123456789012")
	caller := resource.Caller{
		Account: account, Subject: "console", Principal: iam.RootARN(account), Root: true,
	}
	svc := cloud.New(cloud.Config{Backends: fake.New(fake.Options{}).Set()})
	ui := console.New(console.Config{
		Service: svc, IAM: iam.NewStatic("AKIDEXAMPLE", "secret", account),
		Auth: console.BearerTokens{"tok-console": caller},
	})
	cred := sigv4.Credential{AccessKey: "AKIDEXAMPLE", Secret: "secret", Account: account}
	query := ec2query.New(ec2query.Config{
		Service: svc, Authorizer: iam.NewStatic(cred.AccessKey, cred.Secret, cred.Account),
		Verifier: verifier(cred, sigv4.ServiceEC2, now),
	})
	const public = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG417cXtz5jVkH8Cu0D4exQ0iqZ8aXluTLeM0PhuoDH1"
	want := map[string]string{"Name": "login", "team": "a"}
	auth := map[string]string{"Authorization": "Bearer tok-console"}
	for _, action := range []string{"CreateKeyPair", "ImportKeyPair"} {
		for _, source := range []string{"console", "query"} {
			name := source + "-" + action
			if source == "console" {
				body := map[string]any{"keyName": name, "tags": want}
				if action == "ImportKeyPair" {
					body["publicKeyMaterial"] = public
				}
				raw, err := json.Marshal(body)
				if err != nil {
					t.Fatal(err)
				}
				rec := call(t, ui, http.MethodPost, "/api/v1/key-pairs", string(raw), map[string]string{
					"Authorization": "Bearer tok-console", "Content-Type": "application/json", "Idempotency-Key": name,
				})
				if rec.Code != http.StatusAccepted {
					t.Fatalf("console %s: %d %s", action, rec.Code, rec.Body)
				}
				form := url.Values{"Action": {"DescribeKeyPairs"}, "Version": {ec2query.Version}, "KeyName.1": {name}}
				described := serveSigned(t, query, cred, sigv4.ServiceEC2, now,
					http.MethodPost, "http://127.0.0.1:8081/", form.Encode())
				var page struct {
					Items []struct {
						Tags []struct {
							Key   string `xml:"key"`
							Value string `xml:"value"`
						} `xml:"tagSet>item"`
					} `xml:"keySet>item"`
				}
				if described.Code != http.StatusOK || xml.Unmarshal(described.Body.Bytes(), &page) != nil ||
					len(page.Items) != 1 {
					t.Fatalf("query describe: %d %s", described.Code, described.Body)
				}
				got := map[string]string{}
				for _, tag := range page.Items[0].Tags {
					got[tag.Key] = tag.Value
				}
				if !maps.Equal(got, want) {
					t.Fatalf("console %s -> query tags = %v, want %v", action, got, want)
				}
			} else {
				form := url.Values{
					"Action": {action}, "Version": {ec2query.Version}, "KeyName": {name},
					"TagSpecification.1.ResourceType": {"key-pair"},
					"TagSpecification.1.Tag.1.Key":    {"Name"}, "TagSpecification.1.Tag.1.Value": {"login"},
					"TagSpecification.1.Tag.2.Key": {"team"}, "TagSpecification.1.Tag.2.Value": {"a"},
				}
				if action == "ImportKeyPair" {
					form.Set("PublicKeyMaterial", base64.StdEncoding.EncodeToString([]byte(public)))
				}
				rec := serveSigned(t, query, cred, sigv4.ServiceEC2, now,
					http.MethodPost, "http://127.0.0.1:8081/", form.Encode())
				if rec.Code != http.StatusOK {
					t.Fatalf("query %s: %d %s", action, rec.Code, rec.Body)
				}
				described := call(t, ui, http.MethodGet, "/api/v1/key-pairs", "", auth)
				var page struct {
					Items []struct {
						Name string            `json:"keyName"`
						Tags map[string]string `json:"tags"`
					} `json:"items"`
				}
				if described.Code != http.StatusOK || json.Unmarshal(described.Body.Bytes(), &page) != nil {
					t.Fatalf("console list: %d %s", described.Code, described.Body)
				}
				found := false
				for _, key := range page.Items {
					if key.Name == name {
						found = true
						if !maps.Equal(key.Tags, want) {
							t.Fatalf("query %s -> console tags = %v, want %v", action, key.Tags, want)
						}
					}
				}
				if !found {
					t.Fatalf("query %s key missing from console list", action)
				}
			}
		}
	}
}
