package resource

import (
	"fmt"
	"testing"
)

func TestCheckPVEAPIURLs(t *testing.T) {
	many := func(n int) []string {
		urls := make([]string, n)
		for i := range urls {
			urls[i] = fmt.Sprintf("https://pve%d:8006", i)
		}
		return urls
	}
	for _, tc := range []struct {
		name string
		urls []string
		ok   bool
	}{
		{"one", []string{"https://pve1:8006"}, true},
		{"trailing slash", []string{"https://pve1:8006/"}, true},
		{"sixteen", many(16), true},
		{"none", nil, false},
		{"seventeen", many(17), false},
		{"http", []string{"http://pve1:8006"}, false},
		{"userinfo", []string{"https://u:p@pve1:8006"}, false},
		{"empty userinfo", []string{"https://@pve1:8006"}, false},
		{"query", []string{"https://pve1:8006?a=b"}, false},
		{"empty query", []string{"https://pve1:8006?"}, false},
		{"fragment", []string{"https://pve1:8006#a"}, false},
		{"empty fragment", []string{"https://pve1:8006#"}, false},
		{"path", []string{"https://pve1:8006/api2"}, false},
		{"no host", []string{"https://"}, false},
		{"empty entry", []string{""}, false},
		{"duplicate", []string{"https://pve1:8006", "https://pve1:8006"}, false},
		{"duplicate by case and slash", []string{"https://pve1:8006", "https://PVE1:8006/"}, false},
		{"same host other port", []string{"https://pve1:8006", "https://pve1:8007"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := CheckPVEAPIURLs(tc.urls); (err == nil) != tc.ok {
				t.Fatalf("CheckPVEAPIURLs(%q) = %v, want ok=%v", tc.urls, err, tc.ok)
			}
		})
	}
}
