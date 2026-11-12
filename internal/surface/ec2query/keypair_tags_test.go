package ec2query

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestKeyPairTagSpecification(t *testing.T) {
	h, cred, now := harness(t)
	send := func(f url.Values) (int, string) {
		t.Helper()
		f.Set("Version", Version)
		res := signed(t, h, cred, now, f.Encode())
		return res.Code, res.Body.String()
	}
	tagged := func(action, name string) url.Values {
		f := url.Values{
			"Action": {action}, "KeyName": {name},
			"TagSpecification.1.ResourceType": {"key-pair"},
			"TagSpecification.1.Tag.1.Key":    {"team"}, "TagSpecification.1.Tag.1.Value": {"a"},
		}
		if action == "ImportKeyPair" {
			f.Set("PublicKeyMaterial", base64.StdEncoding.EncodeToString([]byte(laptopKey)))
		}
		return f
	}
	const tagXML = "<tagSet><item><key>team</key><value>a</value></item></tagSet>"
	for _, action := range []string{"CreateKeyPair", "ImportKeyPair"} {
		code, body := send(tagged(action, strings.ToLower(action)))
		if code != http.StatusOK || !strings.Contains(body, tagXML) {
			t.Fatalf("%s: %d %s, want %s", action, code, body, tagXML)
		}
	}
	code, body := send(url.Values{"Action": {"DescribeKeyPairs"}})
	if code != http.StatusOK || strings.Count(body, tagXML) != 2 {
		t.Fatalf("DescribeKeyPairs %d %s, want two keys with %s", code, body, tagXML)
	}
	for _, action := range []string{"CreateKeyPair", "ImportKeyPair"} {
		for _, invalid := range []string{"resource type", "empty key", "reserved key", "51 tags"} {
			f := tagged(action, "invalid")
			switch invalid {
			case "resource type":
				f.Set("TagSpecification.1.ResourceType", "instance")
			case "empty key":
				f.Set("TagSpecification.1.Tag.1.Key", "")
			case "reserved key":
				f.Set("TagSpecification.1.Tag.1.Key", "aws:team")
			case "51 tags":
				for i := 2; i <= 51; i++ {
					f.Set(fmt.Sprintf("TagSpecification.1.Tag.%d.Key", i), fmt.Sprintf("k%d", i))
					f.Set(fmt.Sprintf("TagSpecification.1.Tag.%d.Value", i), "v")
				}
			}
			code, body := send(f)
			if code != http.StatusBadRequest || !strings.Contains(body, "<Code>InvalidParameterValue</Code>") {
				t.Errorf("%s %s: %d %s, want InvalidParameterValue", action, invalid, code, body)
			}
		}
	}
}
