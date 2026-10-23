package ec2query

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestDescribeImagesMapsOwnerAndPublic(t *testing.T) {
	other, err := resource.Parse[resource.AccountID]("210987654321")
	if err != nil {
		t.Fatal(err)
	}
	id, err := resource.Parse[resource.ImageID]("ami-00000000000000002")
	if err != nil {
		t.Fatal(err)
	}
	public := resource.Image{ID: id, OwnerID: other, Name: "shared", State: "available", Public: true}
	h, cred, now := harnessWithImages(t, []resource.Image{public})
	form := url.Values{"Action": {"DescribeImages"}, "Version": {Version}}
	res := signed(t, h, cred, now, form.Encode())
	if res.Code != http.StatusOK {
		t.Fatalf("%d %s", res.Code, res.Body)
	}
	body := res.Body.String()
	for _, want := range []string{
		"<imageId>" + id.String() + "</imageId>",
		"<imageOwnerId>" + other.String() + "</imageOwnerId>",
		"<isPublic>true</isPublic>",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %s in %s", want, body)
		}
	}
	for _, item := range strings.Split(body, "<item>") {
		if strings.Contains(item, "<imageId>ami-0123456789abcdef0</imageId>") &&
			strings.Contains(item, "<isPublic>true</isPublic>") {
			t.Fatalf("the catalog is public: %s", item)
		}
	}
}

func TestDescribeImagesOwnerSelfHidesPublicImages(t *testing.T) {
	other, err := resource.Parse[resource.AccountID]("210987654321")
	if err != nil {
		t.Fatal(err)
	}
	id, err := resource.Parse[resource.ImageID]("ami-00000000000000002")
	if err != nil {
		t.Fatal(err)
	}
	public := resource.Image{ID: id, OwnerID: other, Name: "shared", State: "available", Public: true}
	h, cred, now := harnessWithImages(t, []resource.Image{public})
	for key := range map[string]struct{}{"Owner.1": {}, "OwnerId.1": {}} {
		form := url.Values{"Action": {"DescribeImages"}, "Version": {Version}, key: {"self"}}
		res := signed(t, h, cred, now, form.Encode())
		if res.Code != http.StatusOK {
			t.Fatalf("%s %d %s", key, res.Code, res.Body)
		}
		if strings.Contains(res.Body.String(), id.String()) {
			t.Fatalf("%s=self kept a public image: %s", key, res.Body)
		}
		if !strings.Contains(res.Body.String(), "ami-0123456789abcdef0") {
			t.Fatalf("%s=self dropped the catalog: %s", key, res.Body)
		}
	}
	foreign := url.Values{"Action": {"DescribeImages"}, "Version": {Version}, "OwnerId.1": {other.String()}}
	foreignRes := signed(t, h, cred, now, foreign.Encode())
	if foreignRes.Code != http.StatusOK || strings.Contains(foreignRes.Body.String(), id.String()) {
		t.Fatalf("foreign owner %d %s", foreignRes.Code, foreignRes.Body)
	}
}

func TestDescribeImagesByPublicID(t *testing.T) {
	other, err := resource.Parse[resource.AccountID]("210987654321")
	if err != nil {
		t.Fatal(err)
	}
	id, err := resource.Parse[resource.ImageID]("ami-00000000000000002")
	if err != nil {
		t.Fatal(err)
	}
	public := resource.Image{ID: id, OwnerID: other, Name: "shared", State: "available", Public: true}
	h, cred, now := harnessWithImages(t, []resource.Image{public})
	form := url.Values{"Action": {"DescribeImages"}, "Version": {Version}, "ImageId.1": {id.String()}}
	res := signed(t, h, cred, now, form.Encode())
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), id.String()) {
		t.Fatalf("%d %s", res.Code, res.Body)
	}
}

func TestDescribeImagesUnknownIDIsAWSNotFound(t *testing.T) {
	h, cred, now := harness(t)
	form := url.Values{
		"Action": {"DescribeImages"}, "Version": {Version}, "ImageId.1": {"ami-00000000000000009"},
	}
	res := signed(t, h, cred, now, form.Encode())
	if res.Code != http.StatusBadRequest {
		t.Fatalf("%d %s", res.Code, res.Body)
	}
	body := res.Body.String()
	for _, want := range []string{
		"<Code>InvalidAMIID.NotFound</Code>",
		"<Message>The image id &#39;[ami-00000000000000009]&#39; does not exist</Message>",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %s in %s", want, body)
		}
	}
}
