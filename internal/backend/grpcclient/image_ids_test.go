package grpcclient

import (
	"context"
	"slices"
	"testing"

	"google.golang.org/grpc/codes"

	computev1 "github.com/popododo0720/vws-proto/gen/go/vws/compute/v1"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// TestImageIDMapping: a compute copy "img-H" is the EC2 "ami-H", a seed
// keeps its id, and an EC2 id names the copy first, then the seed, only when
// it has the 17 digits compute mints.
func TestImageIDMapping(t *testing.T) {
	for _, tc := range []struct {
		local, ec2 string
	}{
		{"img-0c0d0e0f1a2b3c4d5", "ami-0c0d0e0f1a2b3c4d5"},
		{"ami-0c0d0e0f1a2b3c4d5", "ami-0c0d0e0f1a2b3c4d5"},
		{"ami-01234567", "ami-01234567"},
	} {
		got, err := imageIDOf(tc.local)
		if err != nil || got.String() != tc.ec2 {
			t.Fatalf("imageIDOf(%q) = %v %v, want %s", tc.local, got, err, tc.ec2)
		}
	}
	for _, bad := range []string{
		"img-nothex", "img-", "img-01234567", "img-0c0d0e0f1a2b3c4d5f", "snap-0c0d0e0f1a2b3c4d5", "debian-12",
	} {
		if _, err := imageIDOf(bad); err == nil {
			t.Fatalf("imageIDOf(%q) accepted", bad)
		}
	}
	if got := computeImageIDs(mustImage(t, "ami-0c0d0e0f1a2b3c4d5")); !slices.Equal(got,
		[]string{"img-0c0d0e0f1a2b3c4d5", "ami-0c0d0e0f1a2b3c4d5"}) {
		t.Fatalf("17 digits: %v", got)
	}
	if got := computeImageIDs(mustImage(t, "ami-01234567")); !slices.Equal(got, []string{"ami-01234567"}) {
		t.Fatalf("8 digits: %v", got)
	}
}

// TestDescribeImagesReadsACopyAsAnAMI: an image compute copied, own or
// public, is listed under its EC2 id, and the owner check of a foreign one
// reads it under compute's own name.
func TestDescribeImagesReadsACopyAsAnAMI(t *testing.T) {
	caller := mustAccount(t)
	other, err := resource.Parse[resource.AccountID]("210987654321")
	if err != nil {
		t.Fatal(err)
	}
	own := imagePB(t, caller, "img-0c0d0e0f1a2b3c4d5", project(caller), "web-base")
	public := imagePB(t, caller, "img-0a0a0a0a0a0a0a0a0", project(other), "shared")
	srv := &imageListSrv{
		pages:    [][]*computev1.Image{{own, public}},
		getImage: func(string) error { return nil },
	}
	page, err := startImageList(t, srv).DescribeImages(context.Background(), backend.Scope{Account: caller},
		resource.ImageQuery{Page: resource.PageRequest{Size: 50}})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]resource.Image{}
	for _, img := range page.Items {
		got[img.ID.String()] = img
	}
	if img, ok := got["ami-0c0d0e0f1a2b3c4d5"]; !ok || img.OwnerID != caller || img.Name != "web-base" || img.Public {
		t.Fatalf("own copy %+v in %+v", img, page.Items)
	}
	if img, ok := got["ami-0a0a0a0a0a0a0a0a0"]; !ok || img.OwnerID != other || !img.Public {
		t.Fatalf("public copy %+v in %+v", img, page.Items)
	}
	if want := imageName(project(other), "img-0a0a0a0a0a0a0a0a0"); srv.getImageArg != want {
		t.Fatalf("owner check read %q, want %q", srv.getImageArg, want)
	}
}

// TestDescribeImagesCopyWinsASeedOfTheSameDigits: a seed "ami-H" and a copy
// "img-H" are one EC2 id, so DescribeImages lists it once, as the copy, the
// image a launch of that id reads first.
func TestDescribeImagesCopyWinsASeedOfTheSameDigits(t *testing.T) {
	caller := mustAccount(t)
	for name, pages := range map[string][][]*computev1.Image{
		"seed first": {{
			imagePB(t, caller, "ami-0c0d0e0f1a2b3c4d5", project(caller), "seed"),
			imagePB(t, caller, "img-0c0d0e0f1a2b3c4d5", project(caller), "copy"),
		}},
		"copy first": {{
			imagePB(t, caller, "img-0c0d0e0f1a2b3c4d5", project(caller), "copy"),
			imagePB(t, caller, "ami-0c0d0e0f1a2b3c4d5", project(caller), "seed"),
		}},
	} {
		t.Run(name, func(t *testing.T) {
			page, err := startImageList(t, &imageListSrv{pages: pages}).DescribeImages(context.Background(),
				backend.Scope{Account: caller}, resource.ImageQuery{
					IDs: []resource.ImageID{mustImage(t, "ami-0c0d0e0f1a2b3c4d5")}, Page: resource.PageRequest{Size: 50},
				})
			if err != nil || len(page.Items) != 1 || page.Items[0].Name != "copy" {
				t.Fatalf("%v %+v", err, page.Items)
			}
		})
	}
}

// TestMissingCopyKeepsTheImageError: storage or compute naming a missing
// copy "img-H" answers InvalidAMIID.NotFound for "ami-H", as a missing seed
// does, after a volume prefix too.
func TestMissingCopyKeepsTheImageError(t *testing.T) {
	name := imageName(project(mustAccount(t)), "img-0c0d0e0f1a2b3c4d5")
	const want = "The image id '[ami-0c0d0e0f1a2b3c4d5]' does not exist"
	for reason, msg := range map[string]string{
		"RECONCILIATION_FAILED": "image " + name + " not found",
		"VOLUME_FAILED": "volume " + volumeName(project(mustAccount(t)), "vol-0123456789abcdef0") +
			" failed in storage: image " + name + " not found",
	} {
		code := codes.NotFound
		if reason == "VOLUME_FAILED" {
			code = codes.FailedPrecondition
		}
		e := resource.AsError(fromRPC(statusFor(t, code, reason, "vws.dev", msg, false)))
		if e == nil || e.Code != resource.CodeNotFound || e.Kind != resource.KindImage || e.Message != want {
			t.Fatalf("%s: got %#v", reason, e)
		}
	}
}
