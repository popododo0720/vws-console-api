package awscode

import (
	"testing"

	"github.com/popododo0720/vws-lib/errs"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestCodesMatchErrCodes(t *testing.T) {
	for _, c := range resource.Codes() {
		if got, want := Code(c).String(), c.String(); got != want {
			t.Errorf("Code(%v) is %q, want %q", c, got, want)
		}
	}
	for k := resource.KindUnspecified; k.String() != ""; k++ {
		if got, want := Kind(k).String(), k.String(); got != want {
			t.Errorf("Kind(%v) is %q, want %q", k, got, want)
		}
	}
}

func TestAWSEC2TableIsComplete(t *testing.T) {
	for _, c := range errs.Codes() {
		if _, ok := EC2Default[c]; !ok {
			t.Errorf("EC2Default has no entry for %v", c)
		}
	}
	for c, byKind := range EC2ByKind {
		if _, ok := EC2Default[c]; !ok {
			t.Errorf("EC2ByKind overrides %v, but EC2Default has no default for it", c)
		}
		for k, e := range byKind {
			if e.Code == "" || e.HTTP == 0 {
				t.Errorf("EC2ByKind[%v][%v] is empty", c, k)
			}
		}
	}
}

func TestAWSS3TableIsComplete(t *testing.T) {
	for _, c := range errs.Codes() {
		if _, ok := S3Default[c]; !ok {
			t.Errorf("S3Default has no entry for %v", c)
		}
	}
	for c, byKind := range S3ByKind {
		if _, ok := S3Default[c]; !ok {
			t.Errorf("S3ByKind overrides %v, but S3Default has no default for it", c)
		}
		for k, e := range byKind {
			if e.Code == "" || e.HTTP == 0 {
				t.Errorf("S3ByKind[%v][%v] is empty", c, k)
			}
		}
	}
}
