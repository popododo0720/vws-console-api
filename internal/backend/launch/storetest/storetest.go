// Package storetest runs the launch.Store contract shared by persistence backends.
package storetest

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend/launch"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// Run opens an empty store for each case. Create precedes any VM, and collection
// remains writable after undo; those transitions must not require a live VM.
func Run(t *testing.T, open func(*testing.T) launch.Store) {
	t.Helper()
	for _, tc := range []struct {
		name string
		run  func(*testing.T, launch.Store)
	}{
		{"RoundTripAndCAS", roundTrip},
		{"TrackerReplayAndCollection", replayAndCollection},
		{"Lists", lists},
	} {
		t.Run(tc.name, func(t *testing.T) { tc.run(t, open(t)) })
	}
}

func record(t *testing.T) launch.Record {
	t.Helper()
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC)
	return launch.Record{
		Key: strings.Repeat("a", 64), Account: account, Fingerprint: strings.Repeat("f", 64),
		Count: 1, Phase: launch.Running, Attempt: 1, Steps: []launch.Step{}, Started: at, Updated: at,
	}
}

func roundTrip(t *testing.T, s launch.Store) {
	t.Helper()
	ctx := t.Context()
	rec := record(t)
	v1, err := s.Create(ctx, rec)
	if err != nil || v1 == "" {
		t.Fatalf("create version %q: %v", v1, err)
	}
	if _, err := s.Create(ctx, rec); !errors.Is(err, launch.ErrExists) {
		t.Fatalf("second create: %v", err)
	}
	rec.Steps = append(rec.Steps, launch.Step{Kind: launch.StepVolume, Resource: "v"})
	v2, err := s.Update(ctx, rec, v1)
	if err != nil || v2 == "" || v2 == v1 {
		t.Fatalf("update version %q: %v", v2, err)
	}
	if _, err := s.Update(ctx, rec, v1); !errors.Is(err, launch.ErrConflict) {
		t.Fatalf("stale update: %v", err)
	}
	if _, err := s.Update(ctx, rec, ""); err == nil {
		t.Fatal("update without a version overwrote the record")
	}
	got, version, found, err := s.Load(ctx, rec.Key)
	if err != nil || !found || version != v2 || !reflect.DeepEqual(got, rec) {
		t.Fatalf("load %+v %q %v %v", got, version, found, err)
	}
	if _, _, found, err := s.Load(ctx, strings.Repeat("b", 64)); found || err != nil {
		t.Fatalf("absent key: found %v err %v", found, err)
	}
}

func replayAndCollection(t *testing.T, s launch.Store) {
	t.Helper()
	ctx := t.Context()
	rec := record(t)
	begin := func(fp string) (launch.Launch, error) {
		return launch.NewTracker(s, nil).Begin(ctx, rec.Key, rec.Account, fp, rec.Count, nil)
	}
	first, err := begin(rec.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	second, err := begin(rec.Fingerprint)
	if err != nil || !reflect.DeepEqual(first.Record(), second.Record()) {
		t.Fatalf("replay %+v: %v", second.Record(), err)
	}
	if _, err := begin(strings.Repeat("e", 64)); resource.CodeOf(err) != resource.CodeIdempotencyMismatch {
		t.Fatalf("different fingerprint: %v", err)
	}
	for i, l := range []*launch.Launch{&first, &second} {
		if err := l.Done(ctx, launch.Step{Kind: launch.StepVolume, Index: i, Resource: "v"}); err != nil {
			t.Fatal(err)
		}
	}
	got, _, _, err := s.Load(ctx, rec.Key)
	if err != nil || len(got.Steps) != 2 {
		t.Fatalf("racing steps %+v: %v", got.Steps, err)
	}
	if undo, err := second.Undo(ctx); err != nil || !undo {
		t.Fatalf("undo %v: %v", undo, err)
	}
	if err := second.Undone(ctx); err != nil {
		t.Fatal(err)
	}
	if err := second.Collected(ctx, 1); err != nil {
		t.Fatal(err)
	}
	retry, err := begin(rec.Fingerprint)
	if err != nil || retry.Record().Attempt != 2 || retry.Record().Collected != 1 {
		t.Fatalf("retry %+v: %v", retry.Record(), err)
	}
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := s.Update(ctx, got, "stale"); err == nil {
		t.Fatal("canceled update succeeded")
	}
}

func lists(t *testing.T, s launch.Store) {
	t.Helper()
	rec := record(t)
	for i, phase := range []launch.Phase{launch.Running, launch.Undoing, launch.Failed, launch.Succeeded} {
		rec.Key = strings.Repeat(string(rune('a'+i)), 64)
		rec.Phase = phase
		if _, err := s.Create(t.Context(), rec); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		list func(context.Context) ([]launch.Stored, error)
		keys []string
	}{
		{s.Unfinished, []string{strings.Repeat("a", 64), strings.Repeat("b", 64)}},
		{s.Uncollected, []string{strings.Repeat("c", 64)}},
	} {
		rows, err := tc.list(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]bool{}
		for _, row := range rows {
			loaded, version, found, err := s.Load(t.Context(), row.Record.Key)
			if err != nil || !found || version != row.Version || !reflect.DeepEqual(loaded, row.Record) {
				t.Fatalf("list/load disagree: %+v: %v", row, err)
			}
			got[row.Record.Key] = true
		}
		for _, key := range tc.keys {
			if !got[key] {
				t.Fatalf("list omitted %s", key)
			}
		}
	}
}
