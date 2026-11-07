package kubestore_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/popododo0720/vws-console-api/internal/backend/launch"
	"github.com/popododo0720/vws-console-api/internal/backend/launch/kubestore"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// env is the kube-apiserver and etcd of this test binary, nil when
// KUBEBUILDER_ASSETS is unset.
var env *envtest.Environment

var namespaces atomic.Int64

func TestMain(m *testing.M) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		if os.Getenv("CI") != "" {
			fmt.Fprintln(os.Stderr, "KUBEBUILDER_ASSETS is unset in CI; the envtest tests would skip")
			os.Exit(1)
		}
		os.Exit(m.Run())
	}
	env = &envtest.Environment{}
	if _, err := env.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "start envtest:", err)
		os.Exit(1)
	}
	code := m.Run()
	if err := env.Stop(); err != nil {
		fmt.Fprintln(os.Stderr, "stop envtest:", err)
	}
	os.Exit(code)
}

// open returns a store over a fresh namespace and a client to inspect it.
func open(t *testing.T) (*kubestore.Store, *kubernetes.Clientset, string) {
	t.Helper()
	if env == nil {
		t.Skip("KUBEBUILDER_ASSETS is unset; envtest needs kube-apiserver and etcd")
	}
	cs, err := kubernetes.NewForConfig(env.Config)
	if err != nil {
		t.Fatal(err)
	}
	ns := fmt.Sprintf("launch-%d-%d", os.Getpid(), namespaces.Add(1))
	if _, err := cs.CoreV1().Namespaces().Create(context.Background(),
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	s, err := kubestore.New(env.Config, ns)
	if err != nil {
		t.Fatal(err)
	}
	return s, cs, ns
}

func account(t *testing.T) resource.AccountID {
	t.Helper()
	a, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	return a
}

const key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestRecordRoundTripsAndWritesAreCompareAndSwap(t *testing.T) {
	ctx := context.Background()
	s, _, _ := open(t)
	rec := launch.Record{
		Key: key, Account: account(t), Fingerprint: "fp", Count: 1, Phase: launch.Running, Steps: []launch.Step{},
	}
	v1, err := s.Create(ctx, rec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create(ctx, rec); !errors.Is(err, launch.ErrExists) {
		t.Fatalf("second create: %v", err)
	}
	rec.Steps = append(rec.Steps, launch.Step{Kind: launch.StepVolume, Resource: "v"})
	v2, err := s.Update(ctx, rec, v1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Update(ctx, rec, v1); !errors.Is(err, launch.ErrConflict) {
		t.Fatalf("stale update: %v", err)
	}
	if _, err := s.Update(ctx, rec, ""); err == nil {
		t.Fatal("update without a resourceVersion overwrote the record")
	}
	got, version, found, err := s.Load(ctx, key)
	if err != nil || !found || version != v2 || len(got.Steps) != 1 || got.Account != rec.Account {
		t.Fatalf("load %+v %q %v %v", got, version, found, err)
	}
	if _, _, found, err := s.Load(ctx, strings.Repeat("f", 64)); found || err != nil {
		t.Fatalf("absent key: found %v err %v", found, err)
	}
}

// TestNoOpRetryLeavesResourceVersion is the vws-deploy#478 zero-writes check:
// retries of a launch that changes nothing keep the ConfigMap's
// resourceVersion.
func TestNoOpRetryLeavesResourceVersion(t *testing.T) {
	ctx := context.Background()
	s, cs, ns := open(t)
	tr := launch.NewTracker(s, nil)
	step := launch.Step{Kind: launch.StepVolume, Resource: "v"}
	plan := func(int) []launch.Step { return []launch.Step{step} }
	l, err := tr.Begin(ctx, key, account(t), "fp", 1, plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Done(ctx, step); err != nil {
		t.Fatal(err)
	}
	if err := l.Succeed(ctx); err != nil {
		t.Fatal(err)
	}
	before, err := cs.CoreV1().ConfigMaps(ns).Get(ctx, kubestore.Name(key), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for range 5 {
		again, err := tr.Begin(ctx, key, account(t), "fp", 1, plan)
		if err != nil {
			t.Fatal(err)
		}
		if err := again.Done(ctx, step); err != nil {
			t.Fatal(err)
		}
		if err := again.Succeed(ctx); err != nil {
			t.Fatal(err)
		}
	}
	after, err := cs.CoreV1().ConfigMaps(ns).Get(ctx, kubestore.Name(key), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if after.ResourceVersion != before.ResourceVersion {
		t.Fatalf("resourceVersion %s -> %s on no-op retries", before.ResourceVersion, after.ResourceVersion)
	}
}

// TestLargestLaunchFitsTheObjectLimit pins that a launch of the most
// instances RunInstances accepts, planned and every step recorded, stays under the
// vws-deploy#478 object limit, and that a record over it is refused.
func TestLargestLaunchFitsTheObjectLimit(t *testing.T) {
	ctx := context.Background()
	s, cs, ns := open(t)
	rec := launch.Record{
		Key: key, Account: account(t), Fingerprint: strings.Repeat("f", 64), Count: 10,
		Phase: launch.Failed, Attempt: 1 << 20, Started: time.Now(), Updated: time.Now(),
	}
	const zone = "projects/a123456789012/zones/vws-1a/"
	for i := range 10 {
		rec.Plan = append(rec.Plan,
			launch.Step{Kind: launch.StepVolume, Index: i, Resource: zone + "volumes/vol-0123456789abcdef0"},
			launch.Step{Kind: launch.StepInstance, Index: i, Resource: zone + "instances/i-0123456789abcdef0"})
	}
	rec.Steps = rec.Plan
	if _, err := s.Create(ctx, rec); err != nil {
		t.Fatal(err)
	}
	cm, err := cs.CoreV1().ConfigMaps(ns).Get(ctx, kubestore.Name(key), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if size := len(cm.Data["launch.json"]); size > kubestore.MaxRecordBytes/32 {
		t.Fatalf("largest launch is %d bytes", size)
	}
	huge := rec
	huge.Key = strings.Repeat("e", 64)
	huge.Fingerprint = strings.Repeat("x", kubestore.MaxRecordBytes)
	if _, err := s.Create(ctx, huge); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("oversized record: %v", err)
	}
}

// TestRacingRequestsLandEveryStep runs two requests with one client token
// against the API server: each write is a compare-and-swap on
// resourceVersion, so the loser reloads and both steps land.
func TestRacingRequestsLandEveryStep(t *testing.T) {
	ctx := context.Background()
	s, _, _ := open(t)
	tr := launch.NewTracker(s, nil)
	first, err := tr.Begin(ctx, key, account(t), "fp", 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := tr.Begin(ctx, key, account(t), "fp", 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	a := launch.Step{Kind: launch.StepVolume, Index: 0, Resource: "a"}
	b := launch.Step{Kind: launch.StepVolume, Index: 1, Resource: "b"}
	if err := first.Done(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := second.Done(ctx, b); err != nil {
		t.Fatal(err)
	}
	got, _, _, err := s.Load(ctx, key)
	if err != nil || len(got.Steps) != 2 || got.Steps[0] != a || got.Steps[1] != b {
		t.Fatalf("steps %+v err %v", got.Steps, err)
	}
}

// TestUpdateOfARemovedRecordIsAConflict: a record deleted under a request is
// ErrConflict, so the tracker reloads and reports it removed.
func TestUpdateOfARemovedRecordIsAConflict(t *testing.T) {
	ctx := context.Background()
	s, cs, ns := open(t)
	rec := launch.Record{Key: key, Account: account(t), Phase: launch.Running, Steps: []launch.Step{}}
	v, err := s.Create(ctx, rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := cs.CoreV1().ConfigMaps(ns).Delete(ctx, kubestore.Name(key), metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Update(ctx, rec, v); !errors.Is(err, launch.ErrConflict) {
		t.Fatalf("update of a removed record: %v", err)
	}
}

// TestCorruptRecordIsAnError: a ConfigMap whose record does not decode, or
// holds another key, is an error, never an absent record a launch would
// overwrite.
func TestCorruptRecordIsAnError(t *testing.T) {
	ctx := context.Background()
	s, cs, ns := open(t)
	for name, data := range map[string]string{
		key:                     "{not json",
		strings.Repeat("a", 64): `{"key":"` + strings.Repeat("b", 64) + `"}`,
	} {
		if _, err := cs.CoreV1().ConfigMaps(ns).Create(ctx, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: kubestore.Name(name)},
			Data:       map[string]string{"launch.json": data},
		}, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
		if _, _, found, err := s.Load(ctx, name); err == nil || found {
			t.Fatalf("%s: found %v err %v", data, found, err)
		}
	}
}

// TestUnfinishedReadsEveryOpenRecordAcrossPages pins that Unfinished
// returns every running or undoing record this package wrote, over more than
// one page, at the version Load reads, and a record written before the phase
// label. It leaves out a succeeded or failed record and a ConfigMap this
// package did not write, and names a corrupt record in its error without
// hiding the others.
func TestUnfinishedReadsEveryOpenRecordAcrossPages(t *testing.T) {
	ctx := context.Background()
	s, cs, ns := open(t)
	want := map[string]string{}
	for i := range kubestore.ListPage + 1 {
		k := fmt.Sprintf("%064x", i)
		phase := launch.Running
		if i%2 == 1 {
			phase = launch.Undoing
		}
		v, err := s.Create(ctx, launch.Record{Key: k, Account: account(t), Phase: phase, Steps: []launch.Step{}})
		if err != nil {
			t.Fatal(err)
		}
		want[k] = v
	}
	for i, phase := range []launch.Phase{launch.Succeeded, launch.Failed} {
		rec := launch.Record{Key: strings.Repeat(strconv.Itoa(i+1), 64), Phase: phase, Steps: []launch.Step{}}
		if _, err := s.Create(ctx, rec); err != nil {
			t.Fatal(err)
		}
	}
	managed := map[string]string{"app.kubernetes.io/managed-by": "vws-console-api"}
	legacy := strings.Repeat("e", 64)
	for name, data := range map[string]string{
		kubestore.Name(strings.Repeat("f", 64)): "{not json",
		kubestore.Name(legacy):                  `{"key":"` + legacy + `","phase":"running"}`,
	} {
		if _, err := cs.CoreV1().ConfigMaps(ns).Create(ctx, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: name, Labels: managed},
			Data:       map[string]string{"launch.json": data},
		}, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	legacyCM, err := cs.CoreV1().ConfigMaps(ns).Get(ctx, kubestore.Name(legacy), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	want[legacy] = legacyCM.ResourceVersion
	if _, err := cs.CoreV1().ConfigMaps(ns).Create(ctx, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "someone-else"},
		Data:       map[string]string{"launch.json": "{not json"},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	got, err := s.Unfinished(ctx)
	if err == nil || !strings.Contains(err.Error(), kubestore.Name(strings.Repeat("f", 64))) {
		t.Fatalf("corrupt record not named: %v", err)
	}
	if strings.Contains(err.Error(), "someone-else") {
		t.Fatalf("listed a ConfigMap this package did not write: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("listed %d records want %d", len(got), len(want))
	}
	for _, s := range got {
		if want[s.Record.Key] != s.Version {
			t.Fatalf("record %s at version %q want %q", s.Record.Key, s.Version, want[s.Record.Key])
		}
	}
}

// TestUncollectedListsRecordsWithADeadAttempt pins the launch GC listing:
// every write labels vws-launch-gc pending while a dead attempt is left and
// done after, Uncollected lists the pending records and the unlabeled
// failed ones written before the label, never an unlabeled succeeded one,
// and a record collected since drops out.
func TestUncollectedListsRecordsWithADeadAttempt(t *testing.T) {
	s, cs, ns := open(t)
	ctx := context.Background()
	recs := map[string]launch.Record{
		"failed":    {Phase: launch.Failed, Attempt: 1},
		"retried":   {Phase: launch.Running, Attempt: 2},
		"succeeded": {Phase: launch.Succeeded, Attempt: 1},
		"collected": {Phase: launch.Succeeded, Attempt: 3, Collected: 2},
	}
	wantLabel := map[string]string{"failed": "pending", "retried": "pending", "succeeded": "done", "collected": "done"}
	versions := map[string]string{}
	for name, rec := range recs {
		rec.Key, rec.Account, rec.Count, rec.Steps = name, account(t), 1, []launch.Step{}
		v, err := s.Create(ctx, rec)
		if err != nil {
			t.Fatal(err)
		}
		versions[name] = v
		cm, err := cs.CoreV1().ConfigMaps(ns).Get(ctx, kubestore.Name(name), metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if got := cm.Labels["vws-launch-gc"]; got != wantLabel[name] {
			t.Fatalf("%s labeled gc %q want %q", name, got, wantLabel[name])
		}
	}
	for key, phase := range map[string]string{"legacy": "failed", "legacy-succeeded": "succeeded"} {
		if _, err := cs.CoreV1().ConfigMaps(ns).Create(ctx, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:   kubestore.Name(key),
				Labels: map[string]string{"app.kubernetes.io/managed-by": "vws-console-api", "vws-launch-phase": phase},
			},
			Data: map[string]string{"launch.json": `{"key":"` + key + `","phase":"` + phase + `","attempt":1,"count":1}`},
		}, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	listed := func() []string {
		t.Helper()
		got, err := s.Uncollected(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var keys []string
		for _, st := range got {
			keys = append(keys, st.Record.Key)
		}
		slices.Sort(keys)
		return keys
	}
	if got := listed(); !slices.Equal(got, []string{"failed", "legacy", "retried"}) {
		t.Fatalf("uncollected %v", got)
	}
	done := recs["failed"]
	done.Key, done.Account, done.Count, done.Steps, done.Collected = "failed", account(t), 1, []launch.Step{}, 1
	if _, err := s.Update(ctx, done, versions["failed"]); err != nil {
		t.Fatal(err)
	}
	if got := listed(); !slices.Equal(got, []string{"legacy", "retried"}) {
		t.Fatalf("uncollected after collecting %v", got)
	}
}
