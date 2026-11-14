package awssdk

import (
	"context"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestCostDecimalSum(t *testing.T) {
	for _, tc := range []struct {
		amounts []string
		want    string
	}{
		{[]string{"0.1", "0.20"}, "0.30"},
		{[]string{"9007199254740993.000000001", "-0.000000002"}, "9007199254740992.999999999"},
		{[]string{"-12.50", "12.5", "0"}, "0.00"},
	} {
		total, scale := new(big.Rat), 0
		for _, amount := range tc.amounts {
			digits, err := addCost(total, amount)
			if err != nil {
				t.Fatal(err)
			}
			scale = max(scale, digits)
		}
		if got := total.FloatString(scale); got != tc.want {
			t.Fatalf("sum %v = %s, want %s", tc.amounts, got, tc.want)
		}
	}
	for _, amount := range []string{"", "NaN", "1/3", "1e2", ".5", "1.", strings.Repeat("9", 129)} {
		if _, err := addCost(new(big.Rat), amount); err == nil {
			t.Fatalf("accepted %q", amount)
		}
	}
}

type costTransport func(*http.Request) (*http.Response, error)

func (f costTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestCostRequestPagingAndFailures(t *testing.T) {
	account, err := resource.Parse[resource.AccountID]("111111111111")
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"pages", "unit", "amount", "missing", "empty", "limit", "failure", "canceled"} {
		t.Run(scenario, func(t *testing.T) {
			calls := 0
			c := &ConnectionClient{client: &http.Client{Transport: costTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				deadline, ok := r.Context().Deadline()
				if !ok || time.Until(deadline) > 2*time.Second ||
					r.Header.Get("Authorization") != "" || r.Header.Get("X-Amz-Security-Token") != "" ||
					r.Header.Get("X-Vws-Aws-Account") != "222222222222" ||
					r.Header.Get("X-Vws-Account") != account.String() ||
					r.Header.Get("X-Vws-Principal") != "principal" ||
					r.Header.Get("X-Vws-Target-Service") != "ce" ||
					r.Header.Get("X-Vws-Target-Region") != "us-east-1" ||
					r.Header.Get("X-Amz-Target") != "AWSInsightsIndexService.GetCostAndUsage" ||
					r.Header.Get("Content-Type") != "application/x-amz-json-1.1" || r.Method != http.MethodPost {
					t.Error("incorrect CE forwarding request")
				}
				var in struct {
					TimePeriod    struct{ Start, End string }
					Granularity   string
					Metrics       []string
					NextPageToken string
				}
				if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
					t.Fatal(err)
				}
				if in.TimePeriod.Start != "2025-11-01" || in.TimePeriod.End != "2026-11-02" ||
					in.Granularity != "MONTHLY" || len(in.Metrics) != 1 || in.Metrics[0] != "UnblendedCost" ||
					calls == 1 && in.NextPageToken != "" || calls > 1 && in.NextPageToken != "next" {
					t.Errorf("incorrect CE body: %+v", in)
				}
				body := `{"ResultsByTime":[{"Total":{"UnblendedCost":{"Amount":"0.1","Unit":"USD"}}}]}`
				status := http.StatusOK
				switch scenario {
				case "pages":
					if calls == 1 {
						body = strings.TrimSuffix(body, "}") + `,"NextPageToken":"next"}`
					}
				case "unit":
					body = `{"ResultsByTime":[{"Total":{"UnblendedCost":{"Amount":"1","Unit":"USD"}}},` +
						`{"Total":{"UnblendedCost":{"Amount":"1","Unit":"EUR"}}}]}`
				case "amount":
					body = strings.ReplaceAll(body, "0.1", "1/3")
				case "missing":
					body = `{"ResultsByTime":[{"Total":{}}]}`
				case "empty":
					body = `{}`
				case "limit":
					body = strings.TrimSuffix(body, "}") + `,"NextPageToken":"next"}`
				case "failure":
					status, body = http.StatusForbidden, `{"__type":"AccessDeniedException","Message":"canary"}`
				case "canceled":
					return nil, r.Context().Err()
				}
				return &http.Response{StatusCode: status, Header: http.Header{
					"Content-Type": {"application/x-amz-json-1.1"},
				}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
			})}}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if scenario == "canceled" {
				cancel()
			}
			amount, unit, err := c.Cost(ctx, resource.Caller{Account: account, Principal: "principal"},
				"222222222222", "2025-11-01", "2026-11-02")
			if scenario == "pages" {
				if err != nil || amount != "0.2" || unit != "USD" || calls != 2 {
					t.Fatalf("cost = %s %s, calls=%d, err=%v", amount, unit, calls, err)
				}
			} else if err == nil || amount != "" || unit != "" || scenario == "limit" && calls != 100 {
				t.Fatalf("invalid response succeeded: %s %s, calls=%d, err=%v", amount, unit, calls, err)
			}
		})
	}
}
