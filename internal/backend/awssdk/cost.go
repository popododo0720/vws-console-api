package awssdk

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/costexplorer"
	"github.com/aws/aws-sdk-go-v2/service/costexplorer/types"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// Cost reads account-wide UnblendedCost through the private proxy.
func (c *ConnectionClient) Cost(
	ctx context.Context, caller resource.Caller, account, from, to string,
) (string, string, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	client := costexplorer.New(costexplorer.Options{
		Region: "us-east-1", Credentials: aws.AnonymousCredentials{}, RetryMaxAttempts: 2,
		BaseEndpoint: aws.String("http://proxy/"),
		HTTPClient: &http.Client{
			Timeout: 2 * time.Second, CheckRedirect: c.client.CheckRedirect,
			Transport: forwardingTransport{
				base: c.client.Transport, service: "ce", awsAccount: account,
				cfg: Config{
					Account: caller.Account.String(), Region: "us-east-1",
					Principal: func(context.Context) string { return caller.Principal },
				},
			},
		},
	})
	input := &costexplorer.GetCostAndUsageInput{
		TimePeriod:  &types.DateInterval{Start: aws.String(from), End: aws.String(to)},
		Granularity: types.GranularityMonthly, Metrics: []string{"UnblendedCost"},
	}
	total, scale, unit := new(big.Rat), 0, ""
	for range 100 {
		page, err := client.GetCostAndUsage(ctx, input)
		if err != nil {
			return "", "", fmt.Errorf("awssdk: cost unavailable: %w", awsError(err))
		}
		for _, period := range page.ResultsByTime {
			value, ok := period.Total["UnblendedCost"]
			if !ok || aws.ToString(value.Unit) == "" || unit != "" && unit != aws.ToString(value.Unit) {
				return "", "", errors.New("awssdk: cost unit unavailable")
			}
			unit = aws.ToString(value.Unit)
			digits, err := addCost(total, aws.ToString(value.Amount))
			if err != nil {
				return "", "", err
			}
			scale = max(scale, digits)
		}
		if aws.ToString(page.NextPageToken) == "" {
			if unit == "" {
				return "", "", errors.New("awssdk: cost total unavailable")
			}
			return total.FloatString(scale), unit, nil
		}
		input.NextPageToken = page.NextPageToken
	}
	return "", "", errors.New("awssdk: cost page limit exceeded")
}

func addCost(total *big.Rat, amount string) (int, error) {
	if len(amount) > 128 || !regexp.MustCompile(`^-?[0-9]+(\.[0-9]+)?$`).MatchString(amount) {
		return 0, errors.New("awssdk: invalid cost amount")
	}
	value, ok := new(big.Rat).SetString(amount)
	if !ok {
		return 0, errors.New("awssdk: invalid cost amount")
	}
	total.Add(total, value)
	_, fraction, _ := strings.Cut(amount, ".")
	return len(fraction), nil
}
