// Package pveclient is the Proxmox VE REST client of the proxmox backend: API
// token auth, a deadline on every call, bounded retries and task waits
// (design.md 3.3.6). Its types never leave internal/backend/proxmox.
package pveclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Call limits.
const (
	// ReadTimeout bounds one read call, its retries included.
	ReadTimeout = 10 * time.Second
	// MaxRetries is how often a connection error, a 5xx or a 596 is retried.
	MaxRetries = 3
	// maxBody bounds a response body; /cluster/resources is the largest.
	maxBody = 64 << 20
)

// Secret is an API token secret. It formats and logs as [redacted].
type Secret string

func (Secret) String() string { return "[redacted]" }

// GoString keeps %#v from printing the secret.
func (Secret) GoString() string { return "[redacted]" }

// LogValue keeps slog from printing the secret.
func (Secret) LogValue() slog.Value { return slog.StringValue("[redacted]") }

// MarshalText keeps JSON and text encoders, slog's included, from printing
// the secret inside a struct.
func (Secret) MarshalText() ([]byte, error) { return []byte("[redacted]"), nil }

// Config describes one PVE API endpoint.
type Config struct {
	// BaseURL is the pveproxy root, such as https://127.0.0.1:8006.
	BaseURL string
	// TokenID is user@realm!tokenname.
	TokenID string
	Secret  Secret
	// HTTPClient carries the node CA. Nil is http.DefaultClient.
	HTTPClient *http.Client
	// Log receives retry records. Nil drops them.
	Log *slog.Logger
	// Backoff is the first retry delay; it doubles per retry. Zero is 200ms.
	Backoff time.Duration
	// PollInterval is the task status poll period before jitter. Zero is 1s.
	PollInterval time.Duration
}

// Client calls one PVE API endpoint.
type Client struct {
	base    *url.URL
	auth    Secret
	http    *http.Client
	log     *slog.Logger
	backoff time.Duration
	poll    time.Duration
	clock   clock
}

// Redact removes this client's credentials from a diagnostic before publication.
func (c *Client) Redact(message string) string {
	auth := string(c.auth)
	message = strings.ReplaceAll(message, auth, "[redacted]")
	id, secret, _ := strings.Cut(strings.TrimPrefix(auth, "PVEAPIToken="), "=")
	message = strings.ReplaceAll(message, secret, "[redacted]")
	return strings.ReplaceAll(message, id, "[redacted]")
}

// New checks cfg and returns its client.
func New(cfg Config) (*Client, error) {
	base, err := url.Parse(cfg.BaseURL)
	if err != nil || (base.Scheme != "https" && base.Scheme != "http") || base.Host == "" {
		return nil, fmt.Errorf("pveclient: base URL %q is not http(s)://host[:port]", cfg.BaseURL)
	}
	user, name, ok := strings.Cut(cfg.TokenID, "!")
	if !ok || !strings.Contains(user, "@") || name == "" {
		return nil, fmt.Errorf("pveclient: token id %q is not user@realm!name", cfg.TokenID)
	}
	if cfg.Secret == "" {
		return nil, errors.New("pveclient: empty token secret")
	}
	c := &Client{
		base: base, auth: Secret("PVEAPIToken=" + cfg.TokenID + "=" + string(cfg.Secret)),
		http: cfg.HTTPClient, log: cfg.Log, backoff: cfg.Backoff, poll: cfg.PollInterval,
		clock: realClock{},
	}
	if c.http == nil {
		c.http = http.DefaultClient
	}
	if c.log == nil {
		c.log = slog.New(slog.DiscardHandler)
	}
	if c.backoff <= 0 {
		c.backoff = 200 * time.Millisecond
	}
	if c.poll <= 0 {
		c.poll = time.Second
	}
	return c, nil
}

// HTTPError is a PVE answer other than 2xx. Message is PVE's reason text.
type HTTPError struct {
	Path    string
	Status  int
	Message string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("pve GET %s: %d %s", e.Path, e.Status, e.Message)
}

// Locked reports whether PVE refused because the VM holds a lock.
func (e *HTTPError) Locked() bool { return strings.Contains(e.Message, "VM is locked") }

// retryable is a connection error, a 5xx or a pveproxy 596, never a 4xx or a
// locked VM or missing pool: neither changes through backoff.
func retryable(err error) bool {
	if he, ok := errors.AsType[*HTTPError](err); ok {
		return he.Status >= 500 && !he.Locked() && !he.poolNotFound()
	}
	return !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded)
}

// get reads path under ReadTimeout into the data field of PVE's envelope.
func get[T any](ctx context.Context, c *Client, path string, q url.Values) (T, error) {
	ctx, cancel := context.WithTimeout(ctx, ReadTimeout)
	defer cancel()
	var out T
	backoff := c.backoff
	for retry := 0; ; retry++ {
		err := c.once(ctx, path, q, &out)
		if err == nil || retry == MaxRetries || !retryable(err) {
			return out, err
		}
		c.log.LogAttrs(ctx, slog.LevelWarn, "pve call retried",
			slog.String("path", path), slog.Int("retry", retry+1), slog.String("error", err.Error()))
		wait := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			wait.Stop()
			return out, fmt.Errorf("%w (retry stopped: %w)", err, ctx.Err())
		case <-wait.C:
		}
		backoff *= 2
	}
}

func (c *Client) once(ctx context.Context, path string, q url.Values, out any) (err error) {
	u := *c.base
	u.Path = strings.TrimSuffix(u.Path, "/") + "/api2/json" + path
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return fmt.Errorf("pve GET %s: %w", path, err)
	}
	req.Header.Set("Authorization", string(c.auth))
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("pve GET %s: %w", path, err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("pve GET %s: close body: %w", path, cerr)
		}
	}()
	body := io.LimitReader(resp.Body, maxBody)
	if resp.StatusCode/100 != 2 {
		msg := strings.TrimSpace(strings.TrimPrefix(resp.Status, fmt.Sprint(resp.StatusCode)))
		var env struct {
			Message string `json:"message"`
		}
		if json.NewDecoder(body).Decode(&env) == nil && env.Message != "" {
			msg = strings.TrimSpace(env.Message)
		}
		return &HTTPError{Path: path, Status: resp.StatusCode, Message: msg}
	}
	env := struct {
		Data any `json:"data"`
	}{Data: out}
	if err := json.NewDecoder(body).Decode(&env); err != nil {
		return fmt.Errorf("pve GET %s: decode: %w", path, err)
	}
	return nil
}

// segment checks a name before it becomes one path segment: no separator,
// no dot segment, no escape.
func segment(kind, s string) (string, error) {
	if s == "" || s == "." || s == ".." {
		return "", fmt.Errorf("pveclient: invalid %s %q", kind, s)
	}
	for _, r := range s {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune(":@!._-", r)
		if !ok {
			return "", fmt.Errorf("pveclient: invalid %s %q", kind, s)
		}
	}
	return "/" + s, nil
}

// jitter spreads d by up to a fifth either way.
func jitter(d time.Duration) time.Duration {
	return d - d/5 + rand.N(2*d/5+1)
}
