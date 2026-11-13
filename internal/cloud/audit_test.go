package cloud

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/popododo0720/vws-lib/obs"
	"go.opentelemetry.io/otel/trace"

	"github.com/popododo0720/vws-console-api/internal/audit"
	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/backend/regionclient"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/throttle"
)

const auditCanary = "secret-token-key-material-body-canary"

func TestEveryKernelMutationAudited(t *testing.T) {
	seen := map[string]bool{}
	for _, typ := range []reflect.Type{
		reflect.TypeFor[backend.Compute](), reflect.TypeFor[backend.Network](), reflect.TypeFor[backend.Storage](),
	} {
		for i := 0; i < typ.NumMethod(); i++ {
			name := typ.Method(i).Name
			if strings.HasPrefix(name, "Describe") || strings.HasPrefix(name, "Get") || strings.HasPrefix(name, "List") {
				continue
			}
			for _, kind := range []resource.RegionKind{resource.RegionKindProxmox, resource.RegionKindAWS} {
				for _, fault := range []error{nil, resource.Denied(auditCanary), resource.Invalid("input", auditCanary)} {
					t.Run(name+"/"+kind.String()+"/"+resource.CodeOf(fault).String(), func(t *testing.T) {
						var lines bytes.Buffer
						set, err := regionclient.New(auditTransport{t: t, fault: fault})
						if err != nil {
							t.Fatal(err)
						}
						svc := New(Config{Backends: set, Audit: audit.New(&lines), Capabilities: backend.AllSupported{Kind: kind}})
						c := caller(t)
						c.Principal, c.Region, c.SourceIP = "arn:vws:iam::123456789012:user/dev", "vws-1", "192.0.2.7"
						ctx := obs.WithRequestID(t.Context(), "audit-request")
						traceID, _ := trace.TraceIDFromHex("0123456789abcdef0123456789abcdef")
						spanID, _ := trace.SpanIDFromHex("0123456789abcdef")
						ctx = trace.ContextWithSpanContext(ctx, trace.NewSpanContext(trace.SpanContextConfig{
							TraceID: traceID, SpanID: spanID,
						}))
						method := reflect.ValueOf(svc).MethodByName(name)
						if !method.IsValid() {
							t.Fatalf("backend mutation %s has no kernel method", name)
						}
						args := []reflect.Value{reflect.ValueOf(ctx), reflect.ValueOf(c)}
						for j := 2; j < method.Type().NumIn(); j++ {
							args = append(args, auditArgument(t, method.Type().In(j)))
						}
						out := method.Call(args)
						var gotErr error
						if v := out[len(out)-1]; !v.IsNil() {
							gotErr = v.Interface().(error)
						}
						if resource.CodeOf(gotErr) != resource.CodeOf(fault) {
							t.Fatalf("mutation result: %v, want %v", gotErr, fault)
						}
						line := oneAuditLine(t, &lines)
						action := name
						if r, ok := args[len(args)-1].Interface().(interface{ Action() resource.Action }); ok {
							action = r.Action().String()
						}
						seen[action] = true
						result, destination, service := "accepted", "pve", "ec2"
						if kind == resource.RegionKindAWS {
							destination = "aws"
						}
						if typ == reflect.TypeFor[backend.Storage]() {
							service = "s3"
						}
						if fault != nil {
							result = "error:" + resource.CodeOf(fault).String()
							if resource.CodeOf(fault) == resource.CodePermissionDenied {
								result = "denied"
							}
						}
						for key, want := range map[string]string{
							"request_id": "audit-request", "trace_id": traceID.String(), "principal_arn": c.Principal,
							"account": c.Account.String(), "region": c.Region, "source_ip": c.SourceIP,
							"destination": destination, "service": service, "action": action, "result": result,
						} {
							if line[key] != want {
								t.Errorf("%s=%v, want %q", key, line[key], want)
							}
						}
						if len(line) != 14 || line["time"] == "" || line["latency_ms"].(float64) < 0 {
							t.Fatalf("schema: %+v", line)
						}
						if service == "ec2" && fault == nil {
							op := out[0].FieldByName("Operation").Interface().(resource.Operation)
							if line["operation_id"] != op.ID.String() ||
								line["resource_ids"].([]any)[0] != op.Targets[0].ID() {
								t.Fatalf("accepted targets: %+v", line)
							}
						} else if line["operation_id"] != "" {
							t.Fatalf("unexpected operation id: %+v", line)
						}
						if name != "CreateVpc" && name != "AllocateAddress" && len(line["resource_ids"].([]any)) == 0 {
							t.Fatalf("named targets missing: %+v", line)
						}
						if strings.Contains(lines.String(), auditCanary) {
							t.Fatalf("request or result material leaked: %s", &lines)
						}
					})
				}
			}
		}
	}
	for _, action := range resource.Actions() {
		if !seen[action.String()] {
			t.Errorf("missing action %s", action)
		}
	}
}

func auditArgument(t *testing.T, typ reflect.Type) reflect.Value {
	t.Helper()
	switch typ {
	case reflect.TypeFor[resource.ClientToken]():
		return reflect.ValueOf(token(t, auditCanary))
	case reflect.TypeFor[io.Reader]():
		return reflect.ValueOf(strings.NewReader(auditCanary))
	}
	value := reflect.New(typ)
	if typ.Kind() != reflect.Struct || typ == reflect.TypeFor[resource.BucketName]() ||
		typ == reflect.TypeFor[resource.ObjectKey]() {
		text := `"audit-bucket"`
		if typ == reflect.TypeFor[resource.ObjectKey]() {
			text = `"audit-key"`
		}
		if err := json.Unmarshal([]byte(text), value.Interface()); err != nil {
			t.Fatal(err)
		}
		return value.Elem()
	}
	data := `{
		"imageId":"ami-0123456789abcdef0","instanceIds":["i-0123456789abcdef0"],
		"instanceType":"vws.small","count":1,"instanceId":"i-0123456789abcdef0",
		"vpcId":"vpc-0123456789abcdef0","vpcIds":["vpc-0123456789abcdef0"],
		"subnetId":"subnet-0123456789abcdef0","subnetIds":["subnet-0123456789abcdef0"],
		"volumeId":"vol-0123456789abcdef0","volumeIds":["vol-0123456789abcdef0"],
		"snapshotId":"snap-0123456789abcdef0","groupId":"sg-0123456789abcdef0",
		"allocationId":"eipalloc-0123456789abcdef0","keyPairId":"key-0123456789abcdef0",
		"cidrBlock":"10.1.0.0/24","availabilityZone":"vws-1a","size":8,"device":"/dev/sdf",
		"groupName":"audit-group","keyName":"audit-key","keyType":"ed25519","name":"audit-image",
		"bucket":"audit-bucket","key":"audit-key",
		"rules":[{"ipProtocol":"tcp","fromPort":22,"toPort":22,"cidrIp":"10.1.0.0/24"}],
		"tags":{"canary":"` + auditCanary + `"},"userData":"` + auditCanary + `",
		"description":"` + auditCanary + `"
	}`
	if field, ok := typ.FieldByName("Tags"); ok && field.Type.Kind() == reflect.Slice {
		data = strings.ReplaceAll(data, `"tags":{"canary":"`+auditCanary+`"}`,
			`"tags":[{"key":"canary","value":"`+auditCanary+`"}]`)
	}
	if err := json.Unmarshal([]byte(data), value.Interface()); err != nil {
		t.Fatal(err)
	}
	return value.Elem()
}

type auditTransport struct {
	t     *testing.T
	fault error
}

func (a auditTransport) Call(_ context.Context, _, _ string, input, req, dst any) error {
	if a.fault != nil {
		return a.fault
	}
	value := reflect.ValueOf(dst).Elem()
	item := value
	if items := value.FieldByName("Items"); items.IsValid() {
		items.Set(reflect.MakeSlice(items.Type(), 1, 1))
		item = items.Index(0)
	}
	for typ, text := range map[reflect.Type]string{
		reflect.TypeFor[resource.InstanceID]():      "i-0123456789abcdef0",
		reflect.TypeFor[resource.VolumeID]():        "vol-0123456789abcdef0",
		reflect.TypeFor[resource.SnapshotID]():      "snap-0123456789abcdef0",
		reflect.TypeFor[resource.ImageID]():         "ami-0123456789abcdef0",
		reflect.TypeFor[resource.VpcID]():           "vpc-0123456789abcdef0",
		reflect.TypeFor[resource.SubnetID]():        "subnet-0123456789abcdef0",
		reflect.TypeFor[resource.SecurityGroupID](): "sg-0123456789abcdef0",
		reflect.TypeFor[resource.AddressID]():       "eipalloc-0123456789abcdef0",
		reflect.TypeFor[resource.KeyPairID]():       "key-0123456789abcdef0",
		reflect.TypeFor[resource.AccountID]():       "123456789012",
		reflect.TypeFor[resource.BucketName]():      "audit-bucket",
		reflect.TypeFor[resource.ObjectKey]():       "audit-key",
	} {
		for i := 0; i < item.NumField(); i++ {
			if field := item.Field(i); field.Type() == typ {
				if err := json.Unmarshal([]byte(`"`+text+`"`), field.Addr().Interface()); err != nil {
					a.t.Fatal(err)
				}
			}
		}
	}
	if field := item.FieldByName("Material"); field.IsValid() {
		field.SetString(auditCanary)
	}
	if op := value.FieldByName("Operation"); op.IsValid() {
		id := item.FieldByName("ID")
		if !id.IsValid() {
			id = item.FieldByName("InstanceID")
		}
		opID, _ := resource.NewOperationID(resource.ServiceCompute, "0123456789abcdef")
		op.Set(reflect.ValueOf(resource.Operation{
			ID: opID, State: resource.OperationSucceeded, OwnerID: input.(backend.Mutation).Account,
			Action:  req.(interface{ Action() resource.Action }).Action(),
			Targets: []resource.Ref{id.Interface().(interface{ Ref() resource.Ref }).Ref()},
		}))
	}
	return nil
}

func oneAuditLine(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	if strings.Count(buf.String(), "\n") != 1 {
		t.Fatalf("want exactly one audit line: %s", buf)
	}
	var line map[string]any
	if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
		t.Fatal(err)
	}
	return line
}

func TestAuditRetryRestartReadsAndBoundaries(t *testing.T) {
	var buf bytes.Buffer
	set := world(t).Set()
	cfg := Config{Backends: set, Audit: audit.New(&buf)}
	c := caller(t)
	svc := New(cfg)
	for range 2 {
		_, err := svc.CreateVpc(t.Context(), c, token(t, "audit-retry"), resource.CreateVpcRequest{Cidr: "10.0.0.0/16"})
		if err != nil {
			t.Fatal(err)
		}
		oneAuditLine(t, &buf)
		buf.Reset()
		svc = New(cfg)
	}
	if _, err := svc.DescribeVpcs(t.Context(), c, resource.VpcQuery{}); err != nil || buf.Len() != 0 {
		t.Fatalf("read audited: %v %s", err, &buf)
	}
	for _, ids := range [][]resource.InstanceID{nil, make([]resource.InstanceID, 21)} {
		_, err := svc.StopInstances(t.Context(), c, token(t, "boundary"), resource.StopInstancesRequest{IDs: ids})
		if resource.CodeOf(err) != resource.CodeInvalidArgument ||
			oneAuditLine(t, &buf)["result"] != "error:InvalidArgument" {
			t.Fatalf("boundary: %v %s", err, &buf)
		}
		buf.Reset()
	}
	_, err := svc.RunInstances(t.Context(), c, resource.ClientToken{}, runReq(t))
	if err == nil || oneAuditLine(t, &buf)["result"] != "error:InvalidArgument" {
		t.Fatalf("missing token: %v %s", err, &buf)
	}
	buf.Reset()
	_, err = svc.CreateKeyPair(t.Context(), c, token(t, "import"), resource.CreateKeyPairRequest{
		Name: "audit-key", PublicKey: auditCanary,
	})
	if err == nil || oneAuditLine(t, &buf)["action"] != "ImportKeyPair" || strings.Contains(buf.String(), auditCanary) {
		t.Fatalf("import material: %v %s", err, &buf)
	}
}

type auditWriteFailure struct{}

func (auditWriteFailure) Write([]byte) (int, error) { return 0, errors.New(auditCanary) }

func TestAuditWriteFailurePreservesMutation(t *testing.T) {
	svc := New(Config{Backends: world(t).Set(), Audit: audit.New(auditWriteFailure{})})
	if _, err := svc.CreateVpc(t.Context(), caller(t), token(t, "audit-failure"),
		resource.CreateVpcRequest{Cidr: "10.0.0.0/16"}); err != nil {
		t.Fatal(err)
	}
}

func TestAuditPreflightFailures(t *testing.T) {
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	for _, tc := range []struct {
		name string
		cfg  Config
		ctx  context.Context
		req  resource.RunInstancesRequest
		want string
	}{
		{"normalize", Config{}, t.Context(), resource.RunInstancesRequest{}, "error:InvalidArgument"},
		{
			"capability",
			Config{Capabilities: stubCapabilities{err: resource.Denied("refused")}},
			t.Context(), runReq(t), "denied",
		},
		{"admission", Config{Capabilities: stubCapabilities{doc: resource.RegionCapabilities{
			Actions: map[string]resource.ActionCapability{"ec2:RunInstances": {State: resource.ActionUnsupported}},
		}}}, t.Context(), runReq(t), "error:InvalidArgument"},
		{"guard", Config{Backends: backend.Set{Compute: foreignCompute{}}}, t.Context(), runReq(t), "error:Internal"},
		{
			"throttle",
			Config{Backends: world(t).Set(), Launches: throttle.NewLaunches(throttle.DefaultLaunchLimits())},
			canceled, runReq(t), "error:ResourceExhausted",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			tc.cfg.Audit = audit.New(&buf)
			_, err := New(tc.cfg).RunInstances(tc.ctx, caller(t), token(t, "preflight"), tc.req)
			if err == nil || oneAuditLine(t, &buf)["result"] != tc.want {
				t.Fatalf("preflight: %v %s", err, &buf)
			}
		})
	}
}

func TestAuditRejectsUnvalidatedNames(t *testing.T) {
	for _, name := range []string{strings.Repeat("oversized", 40), "control\nname"} {
		var buf bytes.Buffer
		svc := New(Config{Backends: world(t).Set(), Audit: audit.New(&buf)})
		c := caller(t)
		for _, call := range []func() error{
			func() error {
				req := runReq(t)
				req.KeyName = name
				_, err := svc.RunInstances(t.Context(), c, resource.ClientToken{}, req)
				return err
			},
			func() error {
				_, err := svc.CreateKeyPair(t.Context(), c, token(t, "invalid-name"),
					resource.CreateKeyPairRequest{Name: name, Type: "invalid"})
				return err
			},
			func() error {
				_, err := svc.DeleteKeyPair(t.Context(), resource.Caller{}, token(t, "invalid-name"),
					resource.DeleteKeyPairRequest{Name: name})
				return err
			},
			func() error {
				_, err := svc.DeleteSecurityGroup(t.Context(), resource.Caller{}, token(t, "invalid-name"),
					resource.DeleteSecurityGroupRequest{Name: name})
				return err
			},
		} {
			if err := call(); err == nil {
				t.Fatal("expected mutation failure")
			}
			for _, id := range oneAuditLine(t, &buf)["resource_ids"].([]any) {
				if id == name {
					t.Fatalf("unvalidated name in audit: %q", id)
				}
			}
			buf.Reset()
		}
	}
}

type auditCatalog struct {
	backend.RegionCatalog
	backend.Capabilities
	reads int
}

func (c *auditCatalog) AWSAccounts(ctx context.Context) ([]backend.AWSAccount, error) {
	c.reads++
	return c.RegionCatalog.AWSAccounts(ctx)
}

func (c *auditCatalog) RegionCapabilities(ctx context.Context, region string) (resource.RegionCapabilities, error) {
	c.reads++
	return c.Capabilities.RegionCapabilities(ctx, region)
}

func TestAuditUsesAdmissionDestination(t *testing.T) {
	for _, failed := range []bool{false, true} {
		var buf bytes.Buffer
		catalog := &auditCatalog{
			RegionCatalog: backend.NewStaticRegions(nil, []backend.AWSAccount{{AllowedRegions: []string{"vws-1"}}}),
			Capabilities:  backend.AllSupported{Kind: resource.RegionKindProxmox},
		}
		want := "pve"
		if failed {
			catalog.Capabilities = stubCapabilities{err: context.Canceled}
			want = "unknown"
		}
		svc := New(Config{Backends: world(t).Set(), Audit: audit.New(&buf), Capabilities: catalog, Regions: catalog})
		_, err := svc.CreateVpc(t.Context(), caller(t), token(t, "destination"),
			resource.CreateVpcRequest{Cidr: "10.0.0.0/16"})
		if (err != nil) != failed || oneAuditLine(t, &buf)["destination"] != want || catalog.reads != 1 {
			t.Fatalf("failed=%v: err=%v, reads=%d, audit=%s", failed, err, catalog.reads, &buf)
		}
	}
}
