package kubestore_test

import (
	"context"
	"errors"
	"fmt"
	"os"
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
	l, err := tr.Begin(ctx, key, account(t), "fp", 1, []launch.Step{step})
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Done(ctx, step); err != nil {
		t.Fatal(err)
	}
	if err := l.Finish(ctx, launch.Succeeded); err != nil {
		t.Fatal(err)
	}
	before, err := cs.CoreV1().ConfigMaps(ns).Get(ctx, kubestore.Name(key), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for range 5 {
		again, err := tr.Begin(ctx, key, account(t), "fp", 1, []launch.Step{step})
		if err != nil {
			t.Fatal(err)
		}
		if err := again.Done(ctx, step); err != nil {
			t.Fatal(err)
		}
		if err := again.Finish(ctx, launch.Succeeded); err != nil {
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
