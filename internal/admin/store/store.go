// Package store keeps operator registrations, Proxmox regions and AWS
// accounts, under the /vws/admin/ prefix of the etcd that holds IAM. Every
// write is a compare-and-swap on the record's version.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Prefix is where the registry lives in etcd.
const Prefix = "/vws/admin/"

// Errors of every Backend and of the Registry.
var (
	ErrNotFound = errors.New("admin store: record not found")
	ErrExists   = errors.New("admin store: record already exists")
	ErrConflict = errors.New("admin store: version does not match")
)

// Version is the compare-and-swap token of a stored record. It is never 0.
type Version int64

// Entry is one stored record.
type Entry struct {
	Key     string
	Value   []byte
	Version Version
}

// Backend stores bytes by key, relative to Prefix. Update and Delete apply
// only at the expected version: ErrNotFound for a missing key, ErrConflict
// for another version.
type Backend interface {
	Create(ctx context.Context, key string, value []byte) (Version, error)
	Get(ctx context.Context, key string) (Entry, error)
	List(ctx context.Context, prefix string) ([]Entry, error)
	Update(ctx context.Context, key string, value []byte, expected Version) (Version, error)
	Delete(ctx context.Context, key string, expected Version) error
}

// Region is one registered Proxmox cluster.
type Region struct {
	Name           string  `json:"name"`
	ClusterName    string  `json:"clusterName"`
	PVEAPIURL      string  `json:"pveApiUrl"`
	CAPEM          string  `json:"caPem,omitempty"`
	TokenID        string  `json:"tokenId"`
	RegionEndpoint string  `json:"regionEndpoint"`
	Zones          []Zone  `json:"zones"`
	Version        Version `json:"-"`
}

// Zone is a node group of a region.
type Zone struct {
	Letter string   `json:"letter"`
	Nodes  []string `json:"nodes"`
}

// AWSAccount is one registered AWS account and the regions it may use.
type AWSAccount struct {
	ID             string   `json:"awsAccountId"`
	RoleARN        string   `json:"roleArn"`
	AllowedRegions []string `json:"allowedRegions"`
	Version        Version  `json:"-"`
}

type record interface {
	name() string
	version() Version
	setVersion(v Version)
}

func (r *Region) name() string         { return r.Name }
func (r *Region) version() Version     { return r.Version }
func (r *Region) setVersion(v Version) { r.Version = v }

func (a *AWSAccount) name() string         { return a.ID }
func (a *AWSAccount) version() Version     { return a.Version }
func (a *AWSAccount) setVersion(v Version) { a.Version = v }

// Registry reads and writes registrations over a Backend.
type Registry struct {
	b Backend
}

// New returns a registry over b.
func New(b Backend) *Registry { return &Registry{b: b} }

// Regions is the collection of Proxmox regions.
func (g *Registry) Regions() Collection[Region, *Region] {
	return Collection[Region, *Region]{b: g.b, kind: "regions/"}
}

// AWSAccounts is the collection of AWS accounts.
func (g *Registry) AWSAccounts() Collection[AWSAccount, *AWSAccount] {
	return Collection[AWSAccount, *AWSAccount]{b: g.b, kind: "aws-accounts/"}
}

// Collection is one kind of registration.
type Collection[T any, P interface {
	*T
	record
}] struct {
	b    Backend
	kind string
}

// Create stores v and returns it with its version.
func (c Collection[T, P]) Create(ctx context.Context, v T) (T, error) {
	key, data, err := c.encode(&v)
	if err != nil {
		return v, err
	}
	ver, err := c.b.Create(ctx, key, data)
	if err != nil {
		return v, fmt.Errorf("create %s: %w", key, err)
	}
	P(&v).setVersion(ver)
	return v, nil
}

// Get reads the record called name.
func (c Collection[T, P]) Get(ctx context.Context, name string) (T, error) {
	var v T
	key, err := c.key(name)
	if err != nil {
		return v, err
	}
	e, err := c.b.Get(ctx, key)
	if err != nil {
		return v, fmt.Errorf("get %s: %w", key, err)
	}
	return decode[T, P](e)
}

// Undecodable is a stored value that is not a valid record. List skips it
// and reports it, so one bad value never hides the others.
type Undecodable struct {
	Key string
	Err error
}

// List reads every decodable record of the collection in name order, and
// reports the values it could not decode.
func (c Collection[T, P]) List(ctx context.Context) ([]T, []Undecodable, error) {
	es, err := c.b.List(ctx, c.kind)
	if err != nil {
		return nil, nil, fmt.Errorf("list %s: %w", c.kind, err)
	}
	out := make([]T, 0, len(es))
	var skipped []Undecodable
	for _, e := range es {
		v, err := decode[T, P](e)
		if err != nil {
			skipped = append(skipped, Undecodable{Key: e.Key, Err: err})
			continue
		}
		out = append(out, v)
	}
	return out, skipped, nil
}

// Update replaces the record if it is still at v.Version.
func (c Collection[T, P]) Update(ctx context.Context, v T) (T, error) {
	key, data, err := c.encode(&v)
	if err != nil {
		return v, err
	}
	ver, err := c.b.Update(ctx, key, data, P(&v).version())
	if err != nil {
		return v, fmt.Errorf("update %s: %w", key, err)
	}
	P(&v).setVersion(ver)
	return v, nil
}

// Delete removes the record called name if it is still at version.
func (c Collection[T, P]) Delete(ctx context.Context, name string, version Version) error {
	key, err := c.key(name)
	if err != nil {
		return err
	}
	if err := c.b.Delete(ctx, key, version); err != nil {
		return fmt.Errorf("delete %s: %w", key, err)
	}
	return nil
}

func (c Collection[T, P]) key(name string) (string, error) {
	if name == "" || strings.ContainsAny(name, "/#\x00") {
		return "", fmt.Errorf("admin store: %q is not a record name", name)
	}
	return c.kind + name, nil
}

func (c Collection[T, P]) encode(v P) (string, []byte, error) {
	key, err := c.key(v.name())
	if err != nil {
		return "", nil, err
	}
	data, err := json.Marshal(v)
	if err != nil {
		return "", nil, fmt.Errorf("encode %s: %w", key, err)
	}
	return key, data, nil
}

func decode[T any, P interface {
	*T
	record
}](e Entry) (T, error) {
	var v T
	if err := json.Unmarshal(e.Value, &v); err != nil {
		return v, fmt.Errorf("decode %s: %w", e.Key, err)
	}
	P(&v).setVersion(e.Version)
	return v, nil
}
