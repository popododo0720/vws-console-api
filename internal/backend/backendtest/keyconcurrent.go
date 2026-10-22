package backendtest

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sshkey"
)

// ConcurrentHarness builds a fresh backend for callers concurrent calls. A
// stub may use callers to hold every call at its first lookup until all of
// them got there, so the calls race deterministically.
type ConcurrentHarness func(callers int) backend.Set

// KeyImportConcurrent is the #287 contract, one table for the fake and the
// gRPC client. Identical ImportKeyPair calls under one client token that
// race are one import: every caller gets the same key pair, and only one
// exists. The same key under other tokens is not that import: EC2
// ImportKeyPair takes no client token, so one call imports the name and the
// rest are InvalidKeyPair.Duplicate.
func KeyImportConcurrent(t *testing.T, newSet ConcurrentHarness) {
	t.Helper()
	ed, err := sshkey.ParsePublic(importedKey)
	if err != nil {
		t.Fatal(err)
	}
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	scope := backend.Scope{Account: account}
	for _, tc := range []struct {
		label     string
		callers   int
		oneToken  bool
		wantWins  int
		wantDupes int
	}{
		{label: "identical imports under one token", callers: 4, oneToken: true, wantWins: 4},
		{label: "the same key under other tokens", callers: 4, wantWins: 1, wantDupes: 3},
	} {
		ctx := context.Background()
		set := newSet(tc.callers)
		const name = "import-race"
		req := resource.CreateKeyPairRequest{Name: name, PublicKey: importedKey}
		type result struct {
			got resource.Accepted[resource.KeyPair]
			err error
		}
		results := make([]result, tc.callers)
		var wg sync.WaitGroup
		for i := range tc.callers {
			token := "k-race"
			if !tc.oneToken {
				token = fmt.Sprintf("k-race-%d", i)
			}
			m := backend.Mutation{Scope: scope, Key: token, Fingerprint: "fp-race"}
			wg.Add(1)
			go func() {
				defer wg.Done()
				got, err := set.Compute.CreateKeyPair(ctx, m, req)
				results[i] = result{got, err}
			}()
		}
		wg.Wait()

		listed, err := set.Compute.DescribeKeyPairs(ctx, scope,
			resource.KeyPairQuery{Names: []string{name}, Page: resource.PageRequest{Size: 50}})
		if err != nil || len(listed.Items) != 1 || listed.Items[0].Fingerprint != ed.AWSFingerprint {
			t.Fatalf("key import race, %s: want one live key pair, got %v %+v", tc.label, err, listed.Items)
		}
		live := listed.Items[0].ID
		wins, dupes := 0, 0
		for i, r := range results {
			var re *resource.Error
			switch {
			case r.err == nil:
				if len(r.got.Items) != 1 || r.got.Items[0].ID != live || r.got.Items[0].Fingerprint != ed.AWSFingerprint {
					t.Fatalf("key import race, %s: caller %d got %+v, want the live key pair %s", tc.label, i, r.got.Items, live)
				}
				wins++
			case errors.As(r.err, &re) && re.Code == resource.CodeAlreadyExists && re.Kind == resource.KindKeyPair &&
				len(r.got.Items) == 0:
				dupes++
			default:
				t.Fatalf("key import race, %s: caller %d: %v %+v", tc.label, i, r.err, r.got.Items)
			}
		}
		if wins != tc.wantWins || dupes != tc.wantDupes {
			t.Fatalf("key import race, %s: %d imported and %d InvalidKeyPair.Duplicate, want %d and %d",
				tc.label, wins, dupes, tc.wantWins, tc.wantDupes)
		}
	}
}
