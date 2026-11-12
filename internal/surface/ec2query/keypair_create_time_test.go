package ec2query

import (
	"encoding/xml"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestDescribeKeyPairsCreateTime(t *testing.T) {
	h, cred, now := harness(t)
	f := url.Values{"Action": {"CreateKeyPair"}, "KeyName": {"dated"}, "Version": {Version}}
	if res := signed(t, h, cred, now, f.Encode()); res.Code != http.StatusOK {
		t.Fatalf("CreateKeyPair %d %s", res.Code, res.Body)
	}
	f = url.Values{"Action": {"DescribeKeyPairs"}, "Version": {Version}}
	res := signed(t, h, cred, now, f.Encode())
	want := "<createTime>2026-10-09T10:00:00.000Z</createTime>"
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), want) {
		t.Fatalf("DescribeKeyPairs %d %s, want %s", res.Code, res.Body, want)
	}
	out, err := xml.Marshal(keyXML(resource.KeyPair{Name: "undated"}))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "createTime") {
		t.Errorf("undated key = %s, want no createTime", out)
	}
}
