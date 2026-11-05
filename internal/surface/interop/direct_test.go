package interop

import (
	"encoding/json"
	"encoding/xml"
	"net/http"
	"net/url"
	"strings"
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

func TestConsoleAndQueryShowTheSameDirectSubnet(t *testing.T) {
	now := time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)
	account := mustParse[resource.AccountID](t, "123456789012")
	caller := resource.Caller{Account: account, Subject: "console", Principal: iam.RootARN(account), Root: true}
	direct := mustParse[resource.SubnetID](t, "subnet-direct-prod")
	world := fake.New(fake.Options{
		Now:    func() time.Time { return now },
		Direct: []fake.DirectNetwork{{ID: direct, Cidr: "192.168.200.0/24"}},
	})
	svc := cloud.New(cloud.Config{Backends: world.Set()})
	ui := console.New(console.Config{
		Service: svc, IAM: iam.NewStatic("AKIDEXAMPLE", "secret", account), Auth: console.BearerTokens{"tok-console": caller},
	})
	cred := sigv4.Credential{AccessKey: "AKIDEXAMPLE", Secret: "secret", Account: account}
	query := ec2query.New(ec2query.Config{
		Service: svc, Authorizer: iam.NewStatic(cred.AccessKey, cred.Secret, cred.Account),
		Verifier: verifier(cred, sigv4.ServiceEC2, now),
	})

	res := call(t, ui, http.MethodGet, "/api/v1/subnets/subnet-direct-prod", "", map[string]string{
		"Authorization": "Bearer tok-console",
	})
	var fromConsole struct {
		ID    string            `json:"subnetId"`
		VpcID string            `json:"vpcId"`
		Cidr  string            `json:"cidrBlock"`
		State string            `json:"state"`
		Zone  string            `json:"availabilityZone"`
		Tags  map[string]string `json:"tags"`
	}
	if res.Code != http.StatusOK || json.Unmarshal(res.Body.Bytes(), &fromConsole) != nil {
		t.Fatalf("console %d %s", res.Code, res.Body)
	}

	form := url.Values{"Action": {"DescribeSubnets"}, "Version": {ec2query.Version}, "SubnetId.1": {"subnet-direct-prod"}}
	qres := serveSigned(t, query, cred, sigv4.ServiceEC2, now, http.MethodPost, "http://127.0.0.1:8081/", form.Encode())
	var fromQuery struct {
		Items []struct {
			ID    string `xml:"subnetId"`
			VpcID string `xml:"vpcId"`
			Cidr  string `xml:"cidrBlock"`
			State string `xml:"state"`
			Zone  string `xml:"availabilityZone"`
			Tags  []struct {
				Key   string `xml:"key"`
				Value string `xml:"value"`
			} `xml:"tagSet>item"`
		} `xml:"subnetSet>item"`
	}
	if qres.Code != http.StatusOK || xml.Unmarshal(qres.Body.Bytes(), &fromQuery) != nil || len(fromQuery.Items) != 1 {
		t.Fatalf("query %d %s", qres.Code, qres.Body)
	}
	q := fromQuery.Items[0]
	if fromConsole.ID != "subnet-direct-prod" || fromConsole.VpcID != "vpc-direct" ||
		fromConsole.Cidr != "192.168.200.0/24" || fromConsole.State != "available" ||
		len(fromConsole.Tags) != 1 || fromConsole.Tags["vws:network-type"] != "direct" {
		t.Fatalf("console subnet %+v", fromConsole)
	}
	if q.ID != fromConsole.ID || q.VpcID != fromConsole.VpcID || q.Cidr != fromConsole.Cidr ||
		q.State != fromConsole.State || q.Zone != fromConsole.Zone ||
		len(q.Tags) != 1 || q.Tags[0].Key != "vws:network-type" || q.Tags[0].Value != "direct" {
		t.Fatalf("query subnet %+v, console %+v", q, fromConsole)
	}
}

// A launch sent on the console and retried on the query surface with the
// same token is one launch, whatever order each lists the interfaces in.
func TestConsoleAndQueryLaunchTheSameMultiInterfaceInstance(t *testing.T) {
	now := time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)
	account := mustParse[resource.AccountID](t, "123456789012")
	caller := resource.Caller{Account: account, Subject: "console", Principal: iam.RootARN(account), Root: true}
	direct := mustParse[resource.SubnetID](t, "subnet-direct-prod")
	world := fake.New(fake.Options{
		Now:    func() time.Time { return now },
		Direct: []fake.DirectNetwork{{ID: direct, Cidr: "192.168.200.0/24"}},
	})
	svc := cloud.New(cloud.Config{Backends: world.Set()})
	ui := console.New(console.Config{
		Service: svc, IAM: iam.NewStatic("AKIDEXAMPLE", "secret", account), Auth: console.BearerTokens{"tok-console": caller},
	})
	cred := sigv4.Credential{AccessKey: "AKIDEXAMPLE", Secret: "secret", Account: account}
	query := ec2query.New(ec2query.Config{
		Service: svc, Authorizer: iam.NewStatic(cred.AccessKey, cred.Secret, cred.Account),
		Verifier: verifier(cred, sigv4.ServiceEC2, now),
	})
	headers := map[string]string{
		"Authorization": "Bearer tok-console", "Content-Type": "application/json", "Idempotency-Key": "launch-nics-1",
	}
	sub := call(t, ui, http.MethodPost, "/api/v1/subnets", `{"cidrBlock":"10.1.0.0/24"}`, map[string]string{
		"Authorization": "Bearer tok-console", "Content-Type": "application/json", "Idempotency-Key": "subnet-nics-1",
	})
	var subAcc struct {
		Items []struct {
			ID string `json:"subnetId"`
		} `json:"items"`
	}
	if sub.Code != http.StatusAccepted || json.Unmarshal(sub.Body.Bytes(), &subAcc) != nil {
		t.Fatalf("subnet %d %s", sub.Code, sub.Body)
	}
	overlay := subAcc.Items[0].ID
	res := call(t, ui, http.MethodPost, "/api/v1/instances",
		`{"imageId":"ami-0123456789abcdef0","instanceType":"vws.small","count":1,"networkInterfaces":[`+
			`{"deviceIndex":0,"subnetId":"`+overlay+`"},{"deviceIndex":1,"subnetId":"subnet-direct-prod"}]}`, headers)
	var acc struct {
		Items []struct {
			ID string `json:"instanceId"`
		} `json:"items"`
	}
	if res.Code != http.StatusAccepted || json.Unmarshal(res.Body.Bytes(), &acc) != nil || len(acc.Items) != 1 {
		t.Fatalf("console %d %s", res.Code, res.Body)
	}
	form := url.Values{
		"Action": {"RunInstances"}, "Version": {ec2query.Version}, "ImageId": {"ami-0123456789abcdef0"},
		"InstanceType": {"vws.small"}, "MinCount": {"1"}, "MaxCount": {"1"}, "ClientToken": {"launch-nics-1"},
		"NetworkInterface.1.DeviceIndex": {"1"}, "NetworkInterface.1.SubnetId": {"subnet-direct-prod"},
		"NetworkInterface.2.DeviceIndex": {"0"}, "NetworkInterface.2.SubnetId": {overlay},
	}
	qres := serveSigned(t, query, cred, sigv4.ServiceEC2, now, http.MethodPost, "http://127.0.0.1:8081/", form.Encode())
	var run struct {
		IDs []string `xml:"instancesSet>item>instanceId"`
	}
	err := xml.Unmarshal(qres.Body.Bytes(), &run)
	if qres.Code != http.StatusOK || err != nil || len(run.IDs) != 1 || run.IDs[0] != acc.Items[0].ID {
		t.Fatalf("query %d %s, want instance %s", qres.Code, qres.Body, acc.Items[0].ID)
	}
	form.Set("NetworkInterface.1.DeviceIndex", "0")
	form.Set("NetworkInterface.2.DeviceIndex", "1")
	moved := serveSigned(t, query, cred, sigv4.ServiceEC2, now, http.MethodPost, "http://127.0.0.1:8081/", form.Encode())
	if moved.Code != http.StatusBadRequest || !strings.Contains(moved.Body.String(), "IdempotentParameterMismatch") {
		t.Fatalf("a retry that moves the primary %d %s", moved.Code, moved.Body)
	}
}
