package interop

import (
	"bytes"
	"encoding"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend/backendtest"
	"github.com/popododo0720/vws-console-api/internal/backend/fake"
	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
	"github.com/popododo0720/vws-console-api/internal/surface/console"
	"github.com/popododo0720/vws-console-api/internal/surface/ec2query"
	"github.com/popododo0720/vws-console-api/internal/surface/iamquery"
	"github.com/popododo0720/vws-console-api/internal/surface/s3rest"
)

func TestConsoleAndQueryLaunchTheSameInstance(t *testing.T) {
	now := time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)
	account := mustParse[resource.AccountID](t, "123456789012")
	caller := resource.Caller{Account: account, Subject: "console", Principal: iam.RootARN(account), Root: true}
	world := fake.New(fake.Options{
		Now:     func() time.Time { return now },
		Entropy: bytes.NewReader(bytes.Repeat([]byte{0x33}, 1<<12)),
	})
	svc := cloud.New(cloud.Config{Backends: world.Set()})
	ui := console.New(console.Config{Service: svc, IAM: iam.NewStatic("AKIDEXAMPLE", "secret", account), Auth: console.BearerTokens{"tok-console": caller}})
	cred := sigv4.Credential{AccessKey: "AKIDEXAMPLE", Secret: "secret", Account: account}
	query := ec2query.New(ec2query.Config{Service: svc, Authorizer: iam.NewStatic(cred.AccessKey, cred.Secret, cred.Account), Verifier: verifier(cred, sigv4.ServiceEC2, now)})

	subnetRes := call(t, ui, http.MethodPost, "/api/v1/subnets", `{"cidrBlock":"10.1.0.0/24"}`, map[string]string{
		"Authorization":   "Bearer tok-console",
		"Content-Type":    "application/json",
		"Idempotency-Key": "subnet-web-1",
	})
	if subnetRes.Code != http.StatusAccepted {
		t.Fatalf("subnet %d %s", subnetRes.Code, subnetRes.Body)
	}
	var subnetAccepted struct {
		Items []struct {
			ID string `json:"subnetId"`
		} `json:"items"`
	}
	if err := json.Unmarshal(subnetRes.Body.Bytes(), &subnetAccepted); err != nil {
		t.Fatal(err)
	}
	subnetID := subnetAccepted.Items[0].ID
	body := `{"imageId":"ami-0123456789abcdef0","instanceType":"vws.small","subnetId":"` + subnetID + `","count":1}`
	consoleRes := call(t, ui, http.MethodPost, "/api/v1/instances", body, map[string]string{
		"Authorization":   "Bearer tok-console",
		"Content-Type":    "application/json",
		"Idempotency-Key": "launch-web-1",
	})
	if consoleRes.Code != http.StatusAccepted {
		t.Fatalf("console %d %s", consoleRes.Code, consoleRes.Body)
	}
	var accepted struct {
		Items []struct {
			InstanceID string `json:"instanceId"`
			State      string `json:"state"`
		} `json:"items"`
		Operation struct {
			ID string `json:"id"`
		} `json:"operation"`
	}
	if err := json.Unmarshal(consoleRes.Body.Bytes(), &accepted); err != nil {
		t.Fatal(err)
	}
	if accepted.Items[0].State != "pending" || !strings.HasPrefix(accepted.Operation.ID, "op-compute-") {
		t.Fatalf("%s", consoleRes.Body)
	}

	form := url.Values{}
	form.Set("Action", "RunInstances")
	form.Set("Version", ec2query.Version)
	form.Set("ImageId", "ami-0123456789abcdef0")
	form.Set("InstanceType", "vws.small")
	form.Set("SubnetId", subnetID)
	form.Set("MinCount", "1")
	form.Set("MaxCount", "1")
	form.Set("ClientToken", "launch-web-1")
	queryRes := serveSigned(t, query, cred, sigv4.ServiceEC2, now, http.MethodPost, "http://127.0.0.1:8081/", form.Encode())
	if queryRes.Code != http.StatusOK || !strings.Contains(queryRes.Body.String(), accepted.Items[0].InstanceID) {
		t.Fatalf("query %d %s", queryRes.Code, queryRes.Body)
	}

	got := call(t, ui, http.MethodGet, "/api/v1/instances/"+accepted.Items[0].InstanceID, "", map[string]string{
		"Authorization": "Bearer tok-console",
	})
	if got.Code != http.StatusOK || !strings.Contains(got.Body.String(), `"state":"running"`) {
		t.Fatalf("describe %d %s", got.Code, got.Body)
	}

	describe := url.Values{}
	describe.Set("Action", "DescribeInstances")
	describe.Set("Version", ec2query.Version)
	describe.Set("InstanceId.1", accepted.Items[0].InstanceID)
	dRes := serveSigned(t, query, cred, sigv4.ServiceEC2, now, http.MethodPost, "http://127.0.0.1:8081/", describe.Encode())
	if dRes.Code != http.StatusOK || !strings.Contains(dRes.Body.String(), "<name>running</name>") {
		t.Fatalf("ec2 describe %d %s", dRes.Code, dRes.Body)
	}
}

func TestConsoleAndQueryShareAVpc(t *testing.T) {
	now := time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)
	account := mustParse[resource.AccountID](t, "123456789012")
	caller := resource.Caller{Account: account, Subject: "console", Principal: iam.RootARN(account), Root: true}
	world := fake.New(fake.Options{Now: func() time.Time { return now }})
	svc := cloud.New(cloud.Config{Backends: world.Set()})
	ui := console.New(console.Config{Service: svc, IAM: iam.NewStatic("AKIDEXAMPLE", "secret", account), Auth: console.BearerTokens{"tok-console": caller}})
	cred := sigv4.Credential{AccessKey: "AKIDEXAMPLE", Secret: "secret", Account: account}
	query := ec2query.New(ec2query.Config{Service: svc, Authorizer: iam.NewStatic(cred.AccessKey, cred.Secret, cred.Account), Verifier: verifier(cred, sigv4.ServiceEC2, now)})

	created := call(t, ui, http.MethodPost, "/api/v1/vpcs", `{"cidrBlock":"10.9.0.0/16"}`, map[string]string{
		"Authorization":   "Bearer tok-console",
		"Content-Type":    "application/json",
		"Idempotency-Key": "vpc-web-1",
	})
	if created.Code != http.StatusAccepted || !strings.Contains(created.Body.String(), `"state":"pending"`) {
		t.Fatalf("create %d %s", created.Code, created.Body)
	}
	var acc struct {
		Items []struct {
			ID string `json:"vpcId"`
		} `json:"items"`
		Operation struct {
			ID string `json:"id"`
		} `json:"operation"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &acc); err != nil {
		t.Fatal(err)
	}
	polled := call(t, ui, http.MethodGet, "/api/v1/operations/"+acc.Operation.ID, "", map[string]string{
		"Authorization": "Bearer tok-console",
	})
	if polled.Code != http.StatusOK || !strings.Contains(polled.Body.String(), `"state":"succeeded"`) {
		t.Fatalf("poll %d %s", polled.Code, polled.Body)
	}
	form := url.Values{}
	form.Set("Action", "DescribeVpcs")
	form.Set("Version", ec2query.Version)
	form.Set("VpcId.1", acc.Items[0].ID)
	described := serveSigned(t, query, cred, sigv4.ServiceEC2, now, http.MethodPost, "http://127.0.0.1:8081/", form.Encode())
	if described.Code != http.StatusOK || !strings.Contains(described.Body.String(), acc.Items[0].ID) || !strings.Contains(described.Body.String(), "available") {
		t.Fatalf("query %d %s", described.Code, described.Body)
	}
}

func TestConsoleAndQueryShareAnAddress(t *testing.T) {
	now := time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)
	account := mustParse[resource.AccountID](t, "123456789012")
	caller := resource.Caller{Account: account, Subject: "console", Principal: iam.RootARN(account), Root: true}
	world := fake.New(fake.Options{Now: func() time.Time { return now }})
	svc := cloud.New(cloud.Config{Backends: world.Set()})
	ui := console.New(console.Config{Service: svc, IAM: iam.NewStatic("AKIDEXAMPLE", "secret", account), Auth: console.BearerTokens{"tok-console": caller}})
	cred := sigv4.Credential{AccessKey: "AKIDEXAMPLE", Secret: "secret", Account: account}
	query := ec2query.New(ec2query.Config{Service: svc, Authorizer: iam.NewStatic(cred.AccessKey, cred.Secret, cred.Account), Verifier: verifier(cred, sigv4.ServiceEC2, now)})

	created := call(t, ui, http.MethodPost, "/api/v1/addresses", `{}`, map[string]string{
		"Authorization":   "Bearer tok-console",
		"Content-Type":    "application/json",
		"Idempotency-Key": "addr-web-1",
	})
	if created.Code != http.StatusAccepted || !strings.Contains(created.Body.String(), `"domain":"vpc"`) {
		t.Fatalf("allocate %d %s", created.Code, created.Body)
	}
	var acc struct {
		Items []struct {
			ID       string `json:"allocationId"`
			PublicIP string `json:"publicIp"`
		} `json:"items"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &acc); err != nil {
		t.Fatal(err)
	}
	if acc.Items[0].ID == "" || acc.Items[0].PublicIP == "" {
		t.Fatalf("%s", created.Body)
	}
	form := url.Values{}
	form.Set("Action", "DescribeAddresses")
	form.Set("Version", ec2query.Version)
	form.Set("AllocationId.1", acc.Items[0].ID)
	described := serveSigned(t, query, cred, sigv4.ServiceEC2, now, http.MethodPost, "http://127.0.0.1:8081/", form.Encode())
	if described.Code != http.StatusOK || !strings.Contains(described.Body.String(), acc.Items[0].ID) || !strings.Contains(described.Body.String(), acc.Items[0].PublicIP) {
		t.Fatalf("query %d %s", described.Code, described.Body)
	}
	again := serveSigned(t, query, cred, sigv4.ServiceEC2, now, http.MethodPost, "http://127.0.0.1:8081/", url.Values{
		"Action": {"AllocateAddress"}, "Version": {ec2query.Version}, "ClientToken": {"addr-web-1"},
	}.Encode())
	if again.Code != http.StatusOK || !strings.Contains(again.Body.String(), acc.Items[0].ID) {
		t.Fatalf("retry %d %s", again.Code, again.Body)
	}
}

func TestConsoleAndQueryDetachTheSameVolume(t *testing.T) {
	now := time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)
	account := mustParse[resource.AccountID](t, "123456789012")
	caller := resource.Caller{Account: account, Subject: "console", Principal: iam.RootARN(account), Root: true}
	world := fake.New(fake.Options{Now: func() time.Time { return now }})
	svc := cloud.New(cloud.Config{Backends: world.Set()})
	static := iam.NewStatic("AKIDEXAMPLE", "secret", account)
	ui := console.New(console.Config{Service: svc, IAM: static, Auth: console.BearerTokens{"tok-console": caller}})
	cred := sigv4.Credential{AccessKey: "AKIDEXAMPLE", Secret: "secret", Account: account}
	query := ec2query.New(ec2query.Config{
		Service: svc, Authorizer: static, Verifier: verifier(cred, sigv4.ServiceEC2, now),
	})

	subnetRes := call(t, ui, http.MethodPost, "/api/v1/subnets", `{"cidrBlock":"10.4.0.0/24"}`, map[string]string{
		"Authorization": "Bearer tok-console", "Content-Type": "application/json", "Idempotency-Key": "subnet-detach",
	})
	if subnetRes.Code != http.StatusAccepted {
		t.Fatalf("subnet %d %s", subnetRes.Code, subnetRes.Body)
	}
	var subnetAccepted struct {
		Items []struct {
			ID string `json:"subnetId"`
		} `json:"items"`
	}
	if err := json.Unmarshal(subnetRes.Body.Bytes(), &subnetAccepted); err != nil {
		t.Fatal(err)
	}
	runBody := `{"imageId":"ami-0123456789abcdef0","instanceType":"vws.small","subnetId":"` +
		subnetAccepted.Items[0].ID + `","count":1}`
	runRes := call(t, ui, http.MethodPost, "/api/v1/instances", runBody, map[string]string{
		"Authorization": "Bearer tok-console", "Content-Type": "application/json", "Idempotency-Key": "run-detach",
	})
	if runRes.Code != http.StatusAccepted {
		t.Fatalf("run %d %s", runRes.Code, runRes.Body)
	}
	var runAccepted struct {
		Items []struct {
			ID string `json:"instanceId"`
		} `json:"items"`
	}
	if err := json.Unmarshal(runRes.Body.Bytes(), &runAccepted); err != nil {
		t.Fatal(err)
	}
	inst := runAccepted.Items[0].ID
	volRes := call(t, ui, http.MethodPost, "/api/v1/volumes", `{"size":4,"availabilityZone":"vws-1a"}`, map[string]string{
		"Authorization": "Bearer tok-console", "Content-Type": "application/json", "Idempotency-Key": "vol-detach",
	})
	if volRes.Code != http.StatusAccepted {
		t.Fatalf("volume %d %s", volRes.Code, volRes.Body)
	}
	var volAccepted struct {
		Items []struct {
			ID string `json:"volumeId"`
		} `json:"items"`
	}
	if err := json.Unmarshal(volRes.Body.Bytes(), &volAccepted); err != nil {
		t.Fatal(err)
	}
	vol := volAccepted.Items[0].ID
	attachBody := `{"instanceId":"` + inst + `","device":"/dev/sdf"}`
	attached := call(t, ui, http.MethodPost, "/api/v1/volumes/"+vol+"/attach", attachBody, map[string]string{
		"Authorization": "Bearer tok-console", "Content-Type": "application/json", "Idempotency-Key": "attach-detach",
	})
	if attached.Code != http.StatusAccepted {
		t.Fatalf("attach %d %s", attached.Code, attached.Body)
	}
	detached := serveSigned(t, query, cred, sigv4.ServiceEC2, now, http.MethodPost, "http://127.0.0.1:8081/", url.Values{
		"Action": {"DetachVolume"}, "Version": {ec2query.Version},
		"VolumeId": {vol}, "InstanceId": {inst}, "Device": {"/dev/sdf"},
	}.Encode())
	if detached.Code != http.StatusOK || !strings.Contains(detached.Body.String(), "<status>detaching</status>") ||
		!strings.Contains(detached.Body.String(), vol) {
		t.Fatalf("query detach %d %s", detached.Code, detached.Body)
	}
	deleted := serveSigned(t, query, cred, sigv4.ServiceEC2, now, http.MethodPost, "http://127.0.0.1:8081/", url.Values{
		"Action": {"DeleteVolume"}, "Version": {ec2query.Version}, "VolumeId": {vol},
	}.Encode())
	if deleted.Code != http.StatusOK || !strings.Contains(deleted.Body.String(), "<return>true</return>") {
		t.Fatalf("delete %d %s", deleted.Code, deleted.Body)
	}

	vol2Res := serveSigned(t, query, cred, sigv4.ServiceEC2, now, http.MethodPost, "http://127.0.0.1:8081/", url.Values{
		"Action": {"CreateVolume"}, "Version": {ec2query.Version}, "Size": {"4"},
		"AvailabilityZone": {"vws-1a"}, "ClientToken": {"vol-detach-2"},
	}.Encode())
	if vol2Res.Code != http.StatusOK {
		t.Fatalf("query volume %d %s", vol2Res.Code, vol2Res.Body)
	}
	vol2 := xmlText(t, vol2Res.Body.String(), "volumeId")
	attach2 := serveSigned(t, query, cred, sigv4.ServiceEC2, now, http.MethodPost, "http://127.0.0.1:8081/", url.Values{
		"Action": {"AttachVolume"}, "Version": {ec2query.Version},
		"VolumeId": {vol2}, "InstanceId": {inst}, "Device": {"/dev/sdg"},
	}.Encode())
	if attach2.Code != http.StatusOK {
		t.Fatalf("query attach %d %s", attach2.Code, attach2.Body)
	}
	detachBody := `{"instanceId":"` + inst + `","device":"/dev/sdg"}`
	consoleDetach := call(t, ui, http.MethodPost, "/api/v1/volumes/"+vol2+"/detach", detachBody, map[string]string{
		"Authorization": "Bearer tok-console", "Content-Type": "application/json", "Idempotency-Key": "detach-console",
	})
	body := consoleDetach.Body.String()
	if consoleDetach.Code != http.StatusAccepted || !strings.Contains(body, `"status":"detaching"`) ||
		!strings.Contains(body, vol2) {
		t.Fatalf("console detach %d %s", consoleDetach.Code, consoleDetach.Body)
	}
	consoleDelete := call(t, ui, http.MethodPost, "/api/v1/volumes/"+vol2+"/delete", "", map[string]string{
		"Authorization": "Bearer tok-console", "Content-Type": "application/json", "Idempotency-Key": "delete-console",
	})
	if consoleDelete.Code != http.StatusAccepted {
		t.Fatalf("console delete %d %s", consoleDelete.Code, consoleDelete.Body)
	}
}

func xmlText(t *testing.T, body, tag string) string {
	t.Helper()
	open := "<" + tag + ">"
	closeTag := "</" + tag + ">"
	start := strings.Index(body, open)
	end := strings.Index(body, closeTag)
	if start < 0 || end < start {
		t.Fatalf("no %s in %s", tag, body)
	}
	return body[start+len(open) : end]
}

func TestS3ObjectRoundTrip(t *testing.T) {
	now := time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)
	account := mustParse[resource.AccountID](t, "123456789012")
	world := fake.New(fake.Options{Now: func() time.Time { return now }})
	svc := cloud.New(cloud.Config{Backends: world.Set()})
	cred := sigv4.Credential{AccessKey: "AKIDEXAMPLE", Secret: "secret", Account: account}
	s3 := s3rest.New(s3rest.Config{Service: svc, Authorizer: iam.NewStatic(cred.AccessKey, cred.Secret, cred.Account), Verifier: verifier(cred, sigv4.ServiceS3, now)})

	bucket := "build-logs.example.com"
	bucketRes := serveSigned(t, s3, cred, sigv4.ServiceS3, now, http.MethodPut, "http://127.0.0.1:8082/"+bucket, "")
	if bucketRes.Code != http.StatusOK {
		t.Fatalf("bucket %d %s", bucketRes.Code, bucketRes.Body)
	}
	putRes := serveSigned(t, s3, cred, sigv4.ServiceS3, now, http.MethodPut,
		"http://127.0.0.1:8082/"+bucket+"/a.txt", "hello")
	if putRes.Code != http.StatusOK {
		t.Fatalf("put %d %s", putRes.Code, putRes.Body)
	}
	getRes := serveSigned(t, s3, cred, sigv4.ServiceS3, now, http.MethodGet, "http://127.0.0.1:8082/"+bucket+"/a.txt", "")
	if getRes.Code != http.StatusOK || getRes.Body.String() != "hello" {
		t.Fatalf("get %d %s", getRes.Code, getRes.Body)
	}

	ui := console.New(console.Config{
		Service: svc,
		IAM:     iam.NewStatic("AKIDEXAMPLE", "secret", account),
		Auth:    console.BearerTokens{"tok-console": {Account: account, Subject: "console", Principal: iam.RootARN(account), Root: true}},
	})
	listed := call(t, ui, http.MethodGet, "/api/v1/buckets", "", map[string]string{"Authorization": "Bearer tok-console"})
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), bucket) {
		t.Fatalf("console list %d %s", listed.Code, listed.Body)
	}
	object := call(t, ui, http.MethodGet, "/api/v1/buckets/"+bucket+"/objects/a.txt", "", map[string]string{
		"Authorization": "Bearer tok-console",
	})
	if object.Code != http.StatusOK || !strings.Contains(object.Body.String(), "aGVsbG8=") {
		t.Fatalf("console object %d %s", object.Code, object.Body)
	}
}

func TestMissingResourceStatusIsPerSurface(t *testing.T) {
	now := time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)
	account := mustParse[resource.AccountID](t, "123456789012")
	caller := resource.Caller{
		Account: account, Subject: "console", Principal: iam.RootARN(account), Root: true,
	}
	world := fake.New(fake.Options{Now: func() time.Time { return now }})
	svc := cloud.New(cloud.Config{Backends: world.Set()})
	cred := sigv4.Credential{AccessKey: "AKIDEXAMPLE", Secret: "secret", Account: account}
	ui := console.New(console.Config{
		Service: svc,
		IAM:     iam.NewStatic(cred.AccessKey, cred.Secret, account),
		Auth:    console.BearerTokens{"tok-console": caller},
	})
	query := ec2query.New(ec2query.Config{
		Service:    svc,
		Authorizer: iam.NewStatic(cred.AccessKey, cred.Secret, account),
		Verifier:   verifier(cred, sigv4.ServiceEC2, now),
	})
	objects := s3rest.New(s3rest.Config{
		Service:    svc,
		Authorizer: iam.NewStatic(cred.AccessKey, cred.Secret, account),
		Verifier:   verifier(cred, sigv4.ServiceS3, now),
	})
	directory := iam.NewFake()
	directory.Now = func() time.Time { return now }
	identity := iamquery.New(iamquery.Config{
		Admin:      directory,
		Authorizer: iam.WithRoot(iam.NewStatic(cred.AccessKey, cred.Secret, account), directory),
		IAM:        verifier(cred, sigv4.ServiceIAM, now),
		STS:        verifier(cred, sigv4.ServiceSTS, now),
	})

	volume := call(t, ui, http.MethodGet, "/api/v1/volumes/vol-00000000000000000", "", map[string]string{
		"Authorization": "Bearer tok-console",
	})
	if volume.Code != http.StatusNotFound || !strings.Contains(volume.Body.String(), `"code":"NotFound"`) {
		t.Fatalf("console %d %s", volume.Code, volume.Body)
	}

	ami := serveSigned(t, query, cred, sigv4.ServiceEC2, now, http.MethodPost, "http://127.0.0.1:8081/", url.Values{
		"Action": {"DescribeImages"}, "Version": {ec2query.Version}, "ImageId.1": {"ami-00000000000000000"},
	}.Encode())
	if ami.Code != http.StatusBadRequest || !strings.Contains(ami.Body.String(), "<Code>InvalidAMIID.NotFound</Code>") {
		t.Fatalf("ec2 %d %s", ami.Code, ami.Body)
	}

	bucket := serveSigned(t, objects, cred, sigv4.ServiceS3, now, http.MethodGet, "http://127.0.0.1:8082/missing-logs", "")
	if bucket.Code != http.StatusNotFound || !strings.Contains(bucket.Body.String(), "<Code>NoSuchBucket</Code>") {
		t.Fatalf("s3 bucket %d %s", bucket.Code, bucket.Body)
	}
	made := serveSigned(t, objects, cred, sigv4.ServiceS3, now, http.MethodPut, "http://127.0.0.1:8082/build-logs", "")
	if made.Code != http.StatusOK {
		t.Fatalf("bucket %d %s", made.Code, made.Body)
	}
	keyURL := "http://127.0.0.1:8082/build-logs/missing.txt"
	key := serveSigned(t, objects, cred, sigv4.ServiceS3, now, http.MethodGet, keyURL, "")
	if key.Code != http.StatusNotFound || !strings.Contains(key.Body.String(), "<Code>NoSuchKey</Code>") {
		t.Fatalf("s3 key %d %s", key.Code, key.Body)
	}

	user := serveSigned(t, identity, cred, sigv4.ServiceIAM, now, http.MethodPost, "http://127.0.0.1:8084/", url.Values{
		"Action": {"GetUser"}, "UserName": {"nobody"}, "Version": {iamquery.IAMVersion},
	}.Encode())
	if user.Code != http.StatusNotFound || !strings.Contains(user.Body.String(), "<Code>NoSuchEntity</Code>") {
		t.Fatalf("iam %d %s", user.Code, user.Body)
	}
}

func verifier(cred sigv4.Credential, service sigv4.Service, now time.Time) *sigv4.Verifier {
	return sigv4.NewVerifier(sigv4.Verifier{
		Service: service,
		Region:  resource.RegionName,
		Now:     func() time.Time { return now },
		Auth:    iam.Authenticator(iam.NewStatic(cred.AccessKey, cred.Secret, cred.Account)),
	})
}

func serveSigned(t *testing.T, h http.Handler, cred sigv4.Credential, service sigv4.Service, now time.Time, method, rawURL, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, rawURL, strings.NewReader(body))
	req.Host = req.URL.Host
	if body != "" {
		if service == sigv4.ServiceS3 {
			req.Header.Set("Content-Type", "text/plain")
		} else {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}
	if err := sigv4.Sign(req, cred, service, resource.RegionName, now); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func call(t *testing.T, h http.Handler, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func mustParse[T any, PT interface {
	*T
	encoding.TextUnmarshaler
}](t *testing.T, s string) T {
	t.Helper()
	v, err := resource.Parse[T, PT](s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// An object a cookie session uploads in the console keeps its Content-Type,
// and S3 GetObject and HeadObject answer it (#224).
func TestCookieUploadContentTypeOnS3(t *testing.T) {
	now := time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)
	account := mustParse[resource.AccountID](t, "123456789012")
	svc := cloud.New(cloud.Config{Backends: fake.New(fake.Options{Now: func() time.Time { return now }}).Set()})
	cred := sigv4.Credential{AccessKey: "AKIDEXAMPLE", Secret: "secret", Account: account}
	root := iam.NewStatic(cred.AccessKey, cred.Secret, account)
	s3 := s3rest.New(s3rest.Config{Service: svc, Authorizer: root, Verifier: verifier(cred, sigv4.ServiceS3, now)})
	rec := serveSigned(t, s3, cred, sigv4.ServiceS3, now, http.MethodPut, "http://127.0.0.1:8082/b224", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("bucket %d %s", rec.Code, rec.Body)
	}

	users := iam.NewFake()
	ctx := t.Context()
	if _, err := users.CreateUser(ctx, account, "bob", "/"); err != nil {
		t.Fatal(err)
	}
	grant := backendtest.UserGrant(ctx, t, users, account, "bob")
	if _, err := users.CreateLoginProfile(ctx, account, "bob", "correct horse 1", grant); err != nil {
		t.Fatal(err)
	}
	if err := users.PutInlinePolicy(ctx, account, iam.EntityUser, "bob", "put",
		`{"Statement":[{"Effect":"Allow","Action":"s3:PutObject","Resource":"*"}]}`,
		backendtest.EntityGrant(ctx, t, users, account, iam.EntityUser, "bob"),
	); err != nil {
		t.Fatal(err)
	}
	ui := console.New(console.Config{Service: svc, IAM: iam.WithRoot(root, users)})
	const origin = "http://127.0.0.1:8080"
	login := httptest.NewRequestWithContext(ctx, http.MethodPost, origin+"/api/v1/auth/login",
		strings.NewReader(`{"account":"123456789012","userName":"bob","password":"correct horse 1"}`))
	login.Header.Set("Content-Type", "application/json")
	login.Header.Set("Origin", origin)
	signedIn := httptest.NewRecorder()
	ui.ServeHTTP(signedIn, login)
	if signedIn.Code != http.StatusOK {
		t.Fatalf("login %d %s", signedIn.Code, signedIn.Body)
	}
	put := httptest.NewRequestWithContext(ctx, http.MethodPut, origin+"/api/v1/buckets/b224/objects/logo.png",
		strings.NewReader("\x89PNG"))
	put.Header.Set("Content-Type", "image/png")
	put.Header.Set("Origin", origin)
	for _, c := range signedIn.Result().Cookies() {
		put.AddCookie(c)
		if c.Name == console.CSRFCookie {
			put.Header.Set(console.CSRFHeader, c.Value)
		}
	}
	uploaded := httptest.NewRecorder()
	ui.ServeHTTP(uploaded, put)
	if uploaded.Code != http.StatusOK {
		t.Fatalf("cookie upload %d %s", uploaded.Code, uploaded.Body)
	}

	for _, method := range []string{http.MethodGet, http.MethodHead} {
		rec := serveSigned(t, s3, cred, sigv4.ServiceS3, now, method, "http://127.0.0.1:8082/b224/logo.png", "")
		if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "image/png" {
			t.Errorf("%s %d Content-Type %q", method, rec.Code, rec.Header().Get("Content-Type"))
		}
	}
}
