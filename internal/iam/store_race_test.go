package iam

import (
	"fmt"
	"sync"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// TestConcurrentReadsOfMissingAccountsDoNotRace is #301. A read that finds no
// account for the request must not create one: account creation writes the
// shared map, and a reader holding only RLock would race another reader.
func TestConcurrentReadsOfMissingAccountsDoNotRace(t *testing.T) {
	ctx := t.Context()
	f := NewFake()
	const readers = 64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range readers {
		a, err := resource.Parse[resource.AccountID](fmt.Sprintf("1234567890%02d", i))
		if err != nil {
			t.Fatal(err)
		}
		arn := "arn:vws:iam::" + a.String() + ":policy/missing"
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := f.GetPolicyVersion(ctx, a, arn, "v1"); resource.CodeOf(err) != resource.CodeNotFound {
				t.Errorf("GetPolicyVersion: %v, want NotFound", err)
			}
		}()
	}
	close(start)
	wg.Wait()
}
