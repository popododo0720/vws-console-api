package awssdk

import (
	"context"
	"errors"
	"net"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/aws/smithy-go"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestAWSSDKConfigHasNoCredentials(t *testing.T) {
	typ := reflect.TypeFor[Config]()
	for i := range typ.NumField() {
		field := typ.Field(i)
		for _, word := range []string{"credential", "key", "secret", "token"} {
			if strings.Contains(strings.ToLower(field.Name), word) {
				t.Errorf("credential-like config field: %s", field.Name)
			}
		}
	}
}

func TestAWSSDKInstancesThroughProxy(t *testing.T) {
	b := setup(t, "instances.xml", http.StatusOK)
	account, err := resource.Parse[resource.AccountID]("111111111111")
	if err != nil {
		t.Fatal(err)
	}
	scope := backend.Scope{Account: account, Region: "us-east-1"}
	page, err := b.DescribeInstances(t.Context(), scope, resource.InstanceQuery{Page: resource.PageRequest{Size: 1}})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.NextToken == "" {
		t.Fatalf("first page: %+v", page)
	}
	got := page.Items[0]
	if got.ID.String() != "i-0123456789abcdef0" || got.OwnerID != account ||
		got.ReservationID.String() != "r-0123456789abcdef0" || got.State != resource.InstanceRunning ||
		got.ImageID.String() != "ami-0123456789abcdef0" || got.InstanceType != "t3.micro" ||
		got.Zone != "us-east-1a" || got.PrivateIP != "10.0.0.7" || got.Tags["Name"] != "fixture" ||
		got.SubnetID.String() != "subnet-0123456789abcdef0" || got.VpcID.String() != "vpc-0123456789abcdef0" ||
		got.KeyName != "inventory" || got.RootDeviceName != "/dev/xvda" ||
		len(got.BlockDevices) != 1 || got.BlockDevices[0].VolumeID.String() != "vol-0123456789abcdef0" ||
		got.BlockDevices[0].Status != resource.AttachmentAttached || !got.BlockDevices[0].DeleteOnTermination {
		t.Fatalf("mapped instance: %+v", got)
	}
	next, err := b.DescribeInstances(t.Context(), scope, resource.InstanceQuery{
		Page: resource.PageRequest{Size: 1, Token: page.NextToken},
	})
	if err != nil || len(next.Items) != 1 || next.Items[0].ID.String() != "i-1123456789abcdef0" || next.NextToken != "" {
		t.Fatalf("second page: %+v, %v", next, err)
	}
}

func TestAWSSDKPreservesAWSErrorCode(t *testing.T) {
	for _, tc := range []struct {
		status  int
		fixture string
		awsCode string
		code    resource.Code
	}{
		{http.StatusForbidden, "unauthorized.xml", "UnauthorizedOperation", resource.CodePermissionDenied},
		{http.StatusInternalServerError, "internal-error.xml", "InternalError", resource.CodeUnavailable},
		{http.StatusServiceUnavailable, "unavailable.xml", "ServiceUnavailable", resource.CodeUnavailable},
		{http.StatusTooManyRequests, "throttled.xml", "SlowDown", resource.CodeResourceExhausted},
		{http.StatusBadRequest, "invalid.xml", "InvalidParameterValue", resource.CodeInvalidArgument},
	} {
		t.Run(strconv.Itoa(tc.status), func(t *testing.T) {
			b := setup(t, tc.fixture, tc.status)
			_, err := b.DescribeInstances(t.Context(), backend.Scope{Region: "us-east-1"}, resource.InstanceQuery{})
			var domain *resource.Error
			var api smithy.APIError
			if !errors.As(err, &domain) || domain.Code != tc.code ||
				!errors.As(domain, &api) || api.ErrorCode() != tc.awsCode ||
				!strings.Contains(domain.Message, tc.awsCode) {
				t.Fatalf("want %v with AWS code %s preserved, got %v", tc.code, tc.awsCode, err)
			}
		})
	}
}

func TestAWSSDKDialsOnlySocket(t *testing.T) {
	socket := fixtureSocket(t)
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	b, err := New(Config{
		Socket: socket, Account: "123456789012", Region: "us-east-1",
		Principal: func(context.Context) string { return "principal" },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		conn.Close()
	}()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	conn, err := b.transport.DialContext(ctx, "tcp", "untrusted.invalid:443")
	if err != nil {
		t.Fatal(err)
	}
	network, address := conn.RemoteAddr().Network(), conn.RemoteAddr().String()
	conn.Close()
	<-done
	if network != "unix" || address != socket {
		t.Fatalf("dial escaped proxy socket: %s %s", network, address)
	}
}
