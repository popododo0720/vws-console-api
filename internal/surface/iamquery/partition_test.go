package iamquery

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend/backendtest"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

var wireARNRE = regexp.MustCompile(`<(?:Arn|PolicyArn|SerialNumber)>([^<]*)</`)

// wireARNs returns the ARNs a response names and fails when it names none or
// any of them is outside the aws partition.
func wireARNs(t *testing.T, body string) []string {
	t.Helper()
	var arns []string
	for _, m := range wireARNRE.FindAllStringSubmatch(body, -1) {
		if !strings.HasPrefix(m[1], "arn:aws:") {
			t.Errorf("ARN %q is not in the aws partition: %s", m[1], body)
		}
		arns = append(arns, m[1])
	}
	if len(arns) == 0 {
		t.Errorf("no ARN in %s", body)
	}
	return arns
}

// Every IAM and STS response ARN is in the aws partition, and each ARN a
// response gave is accepted back as a PolicyArn, RoleArn or SerialNumber.
// Authorization still matches the internal vws partition (#430).
func TestIAMAndSTSResponsesUseTheAWSPartition(t *testing.T) {
	h, f, rec, root := harness(t)
	ctx := t.Context()
	iamCall := func(form url.Values) string {
		t.Helper()
		res := call(t, h, root, sigv4.ServiceIAM, form)
		if res.Code != http.StatusOK {
			t.Fatalf("%v: status %d: %s", form, res.Code, res.Body)
		}
		if strings.Contains(res.Body.String(), "arn:vws") {
			t.Errorf("%v: response carries the vws partition: %s", form, res.Body)
		}
		return res.Body.String()
	}

	userARN := wireARNs(t, iamCall(url.Values{"Action": {"CreateUser"}, "UserName": {"bob"}, "Path": {"/eng/"}}))[0]
	if userARN != "arn:aws:iam::123456789012:user/eng/bob" {
		t.Errorf("CreateUser Arn %q", userARN)
	}
	wireARNs(t, iamCall(url.Values{"Action": {"GetUser"}, "UserName": {"bob"}}))
	wireARNs(t, iamCall(url.Values{"Action": {"GetUser"}}))
	wireARNs(t, iamCall(url.Values{"Action": {"ListUsers"}}))
	wireARNs(t, iamCall(url.Values{"Action": {"CreateGroup"}, "GroupName": {"devs"}}))
	iamCall(url.Values{"Action": {"AddUserToGroup"}, "GroupName": {"devs"}, "UserName": {"bob"}})
	wireARNs(t, iamCall(url.Values{"Action": {"GetGroup"}, "GroupName": {"devs"}}))

	trust := `{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"AWS":"*"}}]}`
	roleARN := wireARNs(t, iamCall(url.Values{
		"Action": {"CreateRole"}, "RoleName": {"ops"}, "AssumeRolePolicyDocument": {trust},
	}))[0]
	wireARNs(t, iamCall(url.Values{"Action": {"GetRole"}, "RoleName": {"ops"}}))

	doc := `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
	policyARN := wireARNs(t, iamCall(url.Values{
		"Action": {"CreatePolicy"}, "PolicyName": {"all"}, "PolicyDocument": {doc},
	}))[0]
	wireARNs(t, iamCall(url.Values{"Action": {"GetPolicy"}, "PolicyArn": {policyARN}}))
	iamCall(url.Values{"Action": {"AttachUserPolicy"}, "UserName": {"bob"}, "PolicyArn": {policyARN}})
	attached := wireARNs(t, iamCall(url.Values{"Action": {"ListAttachedUserPolicies"}, "UserName": {"bob"}}))
	if len(attached) != 1 || attached[0] != policyARN {
		t.Errorf("attached %v, want %s", attached, policyARN)
	}

	serial := wireARNs(t, iamCall(url.Values{
		"Action": {"CreateVirtualMFADevice"}, "VirtualMFADeviceName": {"bob-phone"},
	}))[0]
	wireARNs(t, iamCall(url.Values{"Action": {"ListVirtualMFADevices"}}))
	iamCall(url.Values{
		"Action": {"TagMFADevice"}, "SerialNumber": {serial},
		"Tags.member.1.Key": {"k"}, "Tags.member.1.Value": {"v"},
	})
	iamCall(url.Values{"Action": {"DeleteVirtualMFADevice"}, "SerialNumber": {serial}})

	k, err := f.CreateAccessKey(ctx, root.Account, "bob", backendtest.UserGrant(ctx, t, f, root.Account, "bob"))
	if err != nil {
		t.Fatal(err)
	}
	bob := sigv4.Credential{AccessKey: k.AccessKeyID, Secret: k.Secret}
	res := call(t, h, bob, sigv4.ServiceSTS, url.Values{
		"Action": {"AssumeRole"}, "RoleArn": {roleARN}, "RoleSessionName": {"s1"},
	})
	has(t, res, http.StatusOK, `<Arn>arn:aws:sts::123456789012:assumed-role/ops/s1</Arn>`)

	for _, missing := range []string{
		"arn:aws:iam::123456789012:policy/ghost",
		"arn:aws:iam::123456789012:policy/arn:vws:folder/ghost",
	} {
		has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{"Action": {"GetPolicy"}, "PolicyArn": {missing}}),
			http.StatusNotFound, `<Code>NoSuchEntity</Code>`, "Policy "+missing+" does not exist or is not attachable.")
	}

	seen := strings.Join(rec.seen, "\n")
	for _, want := range []string{
		"iam:GetPolicy arn:vws:iam::123456789012:policy/all",
		"iam:DeleteVirtualMFADevice arn:vws:iam::123456789012:mfa/bob-phone",
		"sts:AssumeRole arn:vws:iam::123456789012:role/ops",
	} {
		if !strings.Contains(seen, want) {
			t.Errorf("not authorized as %q: %v", want, rec.seen)
		}
	}
	if strings.Contains(seen, "arn:aws") {
		t.Errorf("authorized on an aws partition ARN: %v", rec.seen)
	}
}

// Only the aws partition is read as vws. Another partition stays a different
// ARN, so it names no entity, and an ARN that only starts like one is left as
// sent.
func TestOnlyTheAWSPartitionIsReadAsVWS(t *testing.T) {
	for in, want := range map[string]string{
		"arn:aws:iam::123456789012:policy/p":    "arn:vws:iam::123456789012:policy/p",
		"arn:vws:iam::123456789012:policy/p":    "arn:vws:iam::123456789012:policy/p",
		"arn:aws-cn:iam::123456789012:policy/p": "arn:aws-cn:iam::123456789012:policy/p",
		"arn:awsx:iam::123456789012:policy/p":   "arn:awsx:iam::123456789012:policy/p",
		"xarn:aws:iam::123456789012:policy/p":   "xarn:aws:iam::123456789012:policy/p",
		"arn:aws":                               "arn:aws",
		"":                                      "",
	} {
		if got := iam.VWSPartition(in); got != want {
			t.Errorf("VWSPartition(%q) = %q, want %q", in, got, want)
		}
		if back := iam.AWSPartition(iam.VWSPartition(in)); strings.HasPrefix(in, "arn:aws:") && back != in {
			t.Errorf("AWSPartition(VWSPartition(%q)) = %q", in, back)
		}
	}
	h, f, _, root := harness(t)
	doc := `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
	if _, err := f.CreatePolicy(t.Context(), root.Account, "p", "/", doc, ""); err != nil {
		t.Fatal(err)
	}
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"GetPolicy"}, "PolicyArn": {"arn:aws:iam::123456789012:policy/p"},
	}), http.StatusOK, `<Arn>arn:aws:iam::123456789012:policy/p</Arn>`)
	has(t, call(t, h, root, sigv4.ServiceIAM, url.Values{
		"Action": {"GetPolicy"}, "PolicyArn": {"arn:aws-cn:iam::123456789012:policy/p"},
	}), http.StatusNotFound, `<Code>NoSuchEntity</Code>`)
}

// A Deny on the vws spelling of an ARN still refuses the aws spelling, since
// an aws ARN is authorized as vws.
func TestDenyOnTheVWSARNHoldsForTheAWSSpelling(t *testing.T) {
	h, f, _, root := harness(t)
	ctx := t.Context()
	doc := `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
	p, err := f.CreatePolicy(ctx, root.Account, "p", "/", doc, "")
	if err != nil {
		t.Fatal(err)
	}
	serial := seedMfaDevice(t, f, root, "bob-phone")
	if _, err := f.CreateUser(ctx, root.Account, "bob", "/"); err != nil {
		t.Fatal(err)
	}
	policy := `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},` +
		`{"Effect":"Deny","Action":["iam:GetPolicy","iam:ListMFADeviceTags"],"Resource":["` + p.ARN + `","` + serial + `"]}]}`
	if err := f.PutInlinePolicy(ctx, root.Account, iam.EntityUser, "bob", "deny", policy,
		backendtest.EntityGrant(ctx, t, f, root.Account, iam.EntityUser, "bob")); err != nil {
		t.Fatal(err)
	}
	k, err := f.CreateAccessKey(ctx, root.Account, "bob", backendtest.UserGrant(ctx, t, f, root.Account, "bob"))
	if err != nil {
		t.Fatal(err)
	}
	bob := sigv4.Credential{AccessKey: k.AccessKeyID, Secret: k.Secret}
	for _, form := range []url.Values{
		{"Action": {"GetPolicy"}, "PolicyArn": {iam.AWSPartition(p.ARN)}},
		{"Action": {"ListMFADeviceTags"}, "SerialNumber": {iam.AWSPartition(serial)}},
	} {
		has(t, call(t, h, bob, sigv4.ServiceIAM, form), http.StatusForbidden, `<Code>AccessDenied</Code>`)
	}
}
