// Package kubestore keeps launch records as ConfigMaps in one Kubernetes
// namespace, under the vws-deploy#478 rules for VWS state in etcd: desired
// state only, small objects, and every write a compare-and-swap on
// resourceVersion. It is the only package that sees Kubernetes types.
package kubestore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/retry"

	"github.com/popododo0720/vws-console-api/internal/backend/launch"
)

const (
	// dataKey is the ConfigMap key that holds the record as JSON.
	dataKey = "launch.json"
	// MaxRecordBytes is the vws-deploy#478 cap on one VWS-written object.
	// It counts the whole ConfigMap as sent plus metadataHeadroom for what
	// the API server adds. A launch of the most instances RunInstances takes
	// stays far under it.
	MaxRecordBytes = 256 << 10
	// metadataHeadroom is kept free for the uid, timestamps and
	// managedFields the API server adds to a written ConfigMap.
	metadataHeadroom = 16 << 10
	// managedBy marks the ConfigMaps this package writes.
	managedBy      = "app.kubernetes.io/managed-by"
	managedByValue = "vws-console-api"
	// attemptTimeout bounds one HTTP request to the Kubernetes API.
	attemptTimeout = 3 * time.Second
	// callTimeout bounds one Load, Create or Update, every retry included:
	// ours and the ones client-go makes on its own for a Retry-After answer.
	callTimeout = 10 * time.Second
	// clientQPS and clientBurst bound this process's request rate to the
	// Kubernetes API.
	clientQPS   = 50
	clientBurst = 100
)

// Store is a launch.Store over the ConfigMaps of one namespace.
type Store struct {
	maps      corev1client.ConfigMapInterface
	namespace string
	budget    time.Duration
}

// Open connects to the cluster. An empty kubeconfig uses $KUBECONFIG, then
// the default kubeconfig path, then the in-cluster service account when
// neither names a cluster. It does not create the namespace.
func Open(kubeconfig, namespace string) (*Store, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	rules.ExplicitPath = kubeconfig
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, nil).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("kubeconfig: %w", err)
	}
	return New(cfg, namespace)
}

// New returns a Store that writes to namespace through cfg.
func New(cfg *rest.Config, namespace string) (*Store, error) {
	return newStore(cfg, namespace, attemptTimeout, callTimeout)
}

func newStore(cfg *rest.Config, namespace string, attempt, budget time.Duration) (*Store, error) {
	if namespace == "" {
		return nil, errors.New("launch store: empty namespace")
	}
	cfg = rest.CopyConfig(cfg)
	cfg.Timeout = attempt
	// client-go's default of 5 requests a second would throttle a few
	// concurrent launches, about 22 writes each at 10 instances, inside
	// this process.
	cfg.QPS, cfg.Burst = clientQPS, clientBurst
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("kubernetes client: %w", err)
	}
	return &Store{maps: cs.CoreV1().ConfigMaps(namespace), namespace: namespace, budget: budget}, nil
}

// Name is the ConfigMap that holds the record for key.
func Name(key string) string { return "launch-" + key }

// Load reads the record for key.
func (s *Store) Load(ctx context.Context, key string) (launch.Record, string, bool, error) {
	var cm *corev1.ConfigMap
	err := retryTransient(ctx, s.budget, func(ctx context.Context) error {
		var err error
		cm, err = s.maps.Get(ctx, Name(key), metav1.GetOptions{})
		return err //nolint:wrapcheck // retryTransient inspects the API error; it is wrapped below
	})
	if apierrors.IsNotFound(err) {
		return launch.Record{}, "", false, nil
	}
	if err != nil {
		return launch.Record{}, "", false, fmt.Errorf("get %s/%s: %w", s.namespace, Name(key), err)
	}
	var rec launch.Record
	if err := json.Unmarshal([]byte(cm.Data[dataKey]), &rec); err != nil {
		return launch.Record{}, "", false, fmt.Errorf("decode %s/%s: %w", s.namespace, cm.Name, err)
	}
	if rec.Key != key {
		return launch.Record{}, "", false, fmt.Errorf("%s/%s holds key %q", s.namespace, cm.Name, rec.Key)
	}
	return rec, cm.ResourceVersion, true, nil
}

// Create writes rec when its key has no ConfigMap.
func (s *Store) Create(ctx context.Context, rec launch.Record) (string, error) {
	cm, err := s.configMap(rec, "")
	if err != nil {
		return "", err
	}
	var out *corev1.ConfigMap
	err = retryTransient(ctx, s.budget, func(ctx context.Context) error {
		var err error
		out, err = s.maps.Create(ctx, cm, metav1.CreateOptions{})
		return err //nolint:wrapcheck // retryTransient inspects the API error; it is wrapped below
	})
	if apierrors.IsAlreadyExists(err) {
		return "", launch.ErrExists
	}
	if err != nil {
		return "", fmt.Errorf("create %s/%s: %w", s.namespace, cm.Name, err)
	}
	return out.ResourceVersion, nil
}

// Update writes rec when version is still the ConfigMap's resourceVersion.
func (s *Store) Update(ctx context.Context, rec launch.Record, version string) (string, error) {
	if version == "" {
		return "", fmt.Errorf("update %s: no resourceVersion", Name(rec.Key))
	}
	cm, err := s.configMap(rec, version)
	if err != nil {
		return "", err
	}
	var out *corev1.ConfigMap
	err = retryTransient(ctx, s.budget, func(ctx context.Context) error {
		var err error
		out, err = s.maps.Update(ctx, cm, metav1.UpdateOptions{})
		return err //nolint:wrapcheck // retryTransient inspects the API error; it is wrapped below
	})
	if apierrors.IsConflict(err) || apierrors.IsNotFound(err) {
		return "", launch.ErrConflict
	}
	if err != nil {
		return "", fmt.Errorf("update %s/%s: %w", s.namespace, cm.Name, err)
	}
	return out.ResourceVersion, nil
}

func (s *Store) configMap(rec launch.Record, version string) (*corev1.ConfigMap, error) {
	data, err := json.Marshal(rec)
	if err != nil {
		return nil, fmt.Errorf("encode %s: %w", Name(rec.Key), err)
	}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:            Name(rec.Key),
			Namespace:       s.namespace,
			ResourceVersion: version,
			Labels:          map[string]string{managedBy: managedByValue},
		},
		Data: map[string]string{dataKey: string(data)},
	}
	whole, err := json.Marshal(cm)
	if err != nil {
		return nil, fmt.Errorf("encode %s: %w", Name(rec.Key), err)
	}
	if len(whole)+metadataHeadroom > MaxRecordBytes {
		return nil, fmt.Errorf("%s is %d bytes with %d bytes of server metadata, over the %d byte limit",
			Name(rec.Key), len(whole), metadataHeadroom, MaxRecordBytes)
	}
	return cm, nil
}

// retryTransient runs call again with bounded backoff while the API server
// answers with an error a retry can clear, or a request times out. A
// conflict, a missing object or a refusal returns at once. The whole call,
// every retry included, ends within budget.
func retryTransient(ctx context.Context, budget time.Duration, call func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	err := retry.OnError(wait.Backoff{Steps: 4, Duration: 50 * time.Millisecond, Factor: 2, Jitter: 0.1},
		func(err error) bool { return ctx.Err() == nil && transient(err) },
		func() error { return call(ctx) })
	return err //nolint:wrapcheck // the caller wraps it with the object name
}

// transient reports whether a retry can clear err.
func transient(err error) bool {
	var netErr net.Error
	return apierrors.IsServerTimeout(err) || apierrors.IsTimeout(err) || apierrors.IsTooManyRequests(err) ||
		apierrors.IsServiceUnavailable(err) || apierrors.IsInternalError(err) ||
		(errors.As(err, &netErr) && netErr.Timeout())
}
