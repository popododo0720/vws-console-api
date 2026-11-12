package iamclient

import (
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sshkey"
)

func TestIAMKeyPairCreateTime(t *testing.T) {
	m := keyPairMutation(t)
	pair, err := sshkey.Generate(resource.KeyTypeEd25519, strings.NewReader(strings.Repeat("a", 36)))
	if err != nil {
		t.Fatal(err)
	}
	created := time.Date(2026, 11, 10, 6, 30, 0, 123000000, time.FixedZone("offset", 3600))
	for _, tc := range []struct {
		name  string
		stamp *timestamppb.Timestamp
		want  time.Time
	}{
		{"present", timestamppb.New(created), created.UTC()},
		{"missing", nil, time.Time{}},
		{"zero", timestamppb.New(time.Time{}), time.Time{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &keyPairServer{key: &iamv1.KeyPair{
				Name:       projectName(m.Account) + "/keyPairs/key-00000000000000001",
				Spec:       &iamv1.KeyPairSpec{KeyName: "login", Region: m.Region, PublicKey: pair.Public},
				CreateTime: tc.stamp,
			}}
			client := New(keyPairConnection(t, s), Options{})
			for range 2 {
				page, err := client.DescribeKeyPairs(t.Context(), m.Scope, resource.KeyPairQuery{})
				if err != nil || len(page.Items) != 1 {
					t.Fatalf("describe = %+v %v", page, err)
				}
				if got := page.Items[0].CreateTime; got != tc.want || got.Location() != time.UTC {
					t.Fatalf("create time = %v, want %v in UTC", got, tc.want)
				}
			}
		})
	}
}
