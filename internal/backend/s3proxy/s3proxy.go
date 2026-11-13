// Package s3proxy forwards Storage calls to an operator's path-style S3 endpoint.
package s3proxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/popododo0720/vws-console-api/internal/admin/secret"
	"github.com/popododo0720/vws-console-api/internal/admin/store"
	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

// Storage holds no resource state or cached project credentials.
type Storage struct {
	endpoint *url.URL
	region   string
	registry *store.Registry
	kek      *secret.Key
	client   *http.Client
}

var _ backend.Storage = (*Storage)(nil)

// New requires an origin, its signing region and the registry KEK.
func New(endpoint, region string, registry *store.Registry, kek *secret.Key) (*Storage, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") ||
		u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" ||
		!regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`).MatchString(region) || registry == nil || kek == nil {
		return nil, resource.Invalid("s3proxy", "endpoint, signing region, registry and KEK are required")
	}
	return &Storage{
		endpoint: u, region: region, registry: registry, kek: kek,
		client: &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}},
	}, nil
}

func unavailable() error {
	return &resource.Error{Code: resource.CodeUnavailable, Message: "S3 origin unavailable"}
}

// The limit applies before XML parsing and to object bytes, including chunked replies.
func bounded(r io.Reader, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, unavailable()
	}
	return b, nil
}

func (s *Storage) send(ctx context.Context, req *http.Request) (*http.Response, error) {
	for attempt := 0; ; attempt++ {
		resp, err := s.client.Do(req)
		if req.Method != http.MethodGet || attempt == 2 ||
			err == nil && resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode < 500 {
			if err != nil {
				return nil, unavailable()
			}
			return resp, nil
		}
		if resp != nil {
			if err := resp.Body.Close(); err != nil {
				return nil, unavailable()
			}
		}
		timer := time.NewTimer(time.Duration(attempt+1) * 20 * time.Millisecond)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return nil, unavailable()
		}
	}
}

func decodeXML(data []byte, dst any) error {
	d := xml.NewDecoder(bytes.NewReader(data))
	if err := d.Decode(dst); err != nil {
		return unavailable()
	}
	var extra any
	if err := d.Decode(&extra); !errors.Is(err, io.EOF) {
		return unavailable()
	}
	return nil
}

func (s *Storage) call(ctx context.Context, sc backend.Scope, method, path string,
	query url.Values, body []byte, headers http.Header,
) ([]byte, http.Header, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	access, value, err := s.registry.OpenRGWKey(ctx, s.kek, sc.Account)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil, resource.Denied("Access Denied")
	}
	if err != nil {
		return nil, nil, unavailable()
	}
	u := *s.endpoint
	u.Path, u.RawPath, u.RawQuery = path, "", query.Encode()
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, nil, unavailable()
	}
	if headers != nil {
		req.Header = headers.Clone()
	}
	if err := sigv4.Sign(req, sigv4.Credential{AccessKey: access, Secret: value},
		sigv4.ServiceS3, s.region, time.Now()); err != nil {
		return nil, nil, unavailable()
	}
	resp, err := s.send(ctx, req)
	if err != nil {
		return nil, nil, unavailable()
	}
	limit := int64(1 << 20)
	if method == http.MethodGet && strings.Count(path, "/") > 1 {
		limit = resource.MaxObjectBytes
	}
	data, err := bounded(resp.Body, limit)
	closeErr := resp.Body.Close()
	if err != nil {
		return nil, nil, err
	}
	if closeErr != nil {
		return nil, nil, unavailable()
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var e struct {
			XMLName xml.Name `xml:"Error"`
			Code    string
		}
		if decodeXML(data, &e) != nil {
			return nil, nil, unavailable()
		}
		kind := resource.KindBucket
		if strings.Count(path, "/") > 1 {
			kind = resource.KindObject
		}
		switch e.Code {
		case "NoSuchBucket":
			return nil, nil, resource.NotFound(resource.KindBucket, "")
		case "NoSuchKey":
			return nil, nil, resource.NotFound(resource.KindObject, "")
		case "BucketAlreadyOwnedByYou":
			return nil, nil, resource.BucketAlreadyOwned("")
		case "BucketAlreadyExists":
			return nil, nil, resource.AlreadyExists(resource.KindBucket, "")
		case "PreconditionFailed":
			return nil, nil, resource.AlreadyExists(resource.KindObject, "")
		case "BucketNotEmpty":
			return nil, nil, resource.Conflict(resource.KindBucket, "", "bucket is not empty")
		case "AccessDenied":
			return nil, nil, resource.NotFound(kind, "")
		case "InvalidArgument":
			return nil, nil, resource.Invalid("origin", "invalid S3 argument")
		default:
			return nil, nil, unavailable()
		}
	}
	return data, resp.Header, nil
}

func (s *Storage) buckets(ctx context.Context, sc backend.Scope) ([]resource.Bucket, error) {
	data, _, err := s.call(ctx, sc, http.MethodGet, "/", nil, nil, nil)
	if err != nil {
		return nil, err
	}
	var doc struct {
		XMLName xml.Name                              `xml:"ListAllMyBucketsResult"`
		Buckets []struct{ Name, CreationDate string } `xml:"Buckets>Bucket"`
	}
	if decodeXML(data, &doc) != nil {
		return nil, unavailable()
	}
	items := make([]resource.Bucket, 0, len(doc.Buckets))
	for _, b := range doc.Buckets {
		name, err := resource.ParseStoredBucketName(b.Name)
		if err != nil {
			return nil, unavailable()
		}
		items = append(items, resource.Bucket{Name: name, OwnerID: sc.Account, CreationDate: b.CreationDate})
	}
	slices.SortFunc(items, func(a, b resource.Bucket) int { return strings.Compare(a.Name.String(), b.Name.String()) })
	return items, nil
}

// CreateBucket preserves the origin's duplicate ownership decision.
func (s *Storage) CreateBucket(
	ctx context.Context, sc backend.Scope, name resource.BucketName,
) (resource.Bucket, error) {
	if _, _, err := s.call(ctx, sc, http.MethodPut, "/"+name.String(), nil, nil, nil); err != nil {
		return resource.Bucket{}, err
	}
	return s.GetBucket(ctx, sc, name)
}

// GetBucket reads authoritative creation metadata from the user's bucket list.
func (s *Storage) GetBucket(ctx context.Context, sc backend.Scope, name resource.BucketName) (resource.Bucket, error) {
	items, err := s.buckets(ctx, sc)
	if err != nil {
		return resource.Bucket{}, err
	}
	for _, b := range items {
		if b.Name == name {
			return b, nil
		}
	}
	return resource.Bucket{}, resource.NotFound(resource.KindBucket, name.String())
}

// ListBuckets pages the current origin list by bucket name.
func (s *Storage) ListBuckets(
	ctx context.Context, sc backend.Scope, q resource.BucketQuery,
) (resource.Page[resource.Bucket], error) {
	q, err := q.Normalize()
	if err != nil {
		return resource.Page[resource.Bucket]{}, err
	}
	items, err := s.buckets(ctx, sc)
	if err != nil {
		return resource.Page[resource.Bucket]{}, err
	}
	start := 0
	for start < len(items) && items[start].Name.String() <= q.Page.Token {
		start++
	}
	end := min(start+q.Page.Size, len(items))
	out := resource.Page[resource.Bucket]{Items: items[start:end]}
	if end < len(items) {
		out.NextToken = items[end-1].Name.String()
	}
	return out, nil
}

// DeleteBucket refuses a nonempty bucket at the origin.
func (s *Storage) DeleteBucket(ctx context.Context, sc backend.Scope, name resource.BucketName) error {
	_, _, err := s.call(ctx, sc, http.MethodDelete, "/"+name.String(), nil, nil, nil)
	return err
}

// PutObject validates and bounds the bytes before signing.
func (s *Storage) PutObject(
	ctx context.Context, sc backend.Scope, req resource.PutObjectRequest, body io.Reader,
) (resource.Object, error) {
	req, err := req.Normalize()
	if err != nil {
		return resource.Object{}, err
	}
	if body == nil {
		body = http.NoBody
	}
	data, err := io.ReadAll(io.LimitReader(body, resource.MaxObjectBytes+1))
	if err != nil {
		return resource.Object{}, unavailable()
	}
	if len(data) > resource.MaxObjectBytes {
		return resource.Object{}, resource.TooLarge("object exceeds 4 MiB")
	}
	if req.Size >= 0 && req.Size != int64(len(data)) {
		return resource.Object{}, resource.Invalid("size", "body length does not match")
	}
	h := http.Header{"Content-Type": {req.ContentType}}
	if req.IfNoneMatch {
		h.Set("If-None-Match", "*")
	}
	_, headers, err := s.call(ctx, sc, http.MethodPut, "/"+req.Bucket.String()+"/"+req.Key.String(), nil, data, h)
	sum := sha256.Sum256(data)
	return resource.Object{
		Bucket: req.Bucket, Key: req.Key, OwnerID: sc.Account, Size: int64(len(data)),
		ContentType: req.ContentType, ETag: headers.Get("ETag"), SHA256: hex.EncodeToString(sum[:]),
	}, err
}

// GetObject bounds and hashes the origin bytes before returning the body.
func (s *Storage) GetObject(
	ctx context.Context, sc backend.Scope, req resource.GetObjectRequest,
) (resource.Object, io.ReadCloser, error) {
	data, h, err := s.call(ctx, sc, http.MethodGet, "/"+req.Bucket.String()+"/"+req.Key.String(), nil, nil, nil)
	if err != nil {
		return resource.Object{}, nil, err
	}
	sum := sha256.Sum256(data)
	return resource.Object{
		Bucket: req.Bucket, Key: req.Key, OwnerID: sc.Account, Size: int64(len(data)),
		ETag: h.Get("ETag"), ContentType: h.Get("Content-Type"), LastModified: h.Get("Last-Modified"),
		SHA256: hex.EncodeToString(sum[:]),
	}, io.NopCloser(bytes.NewReader(data)), nil
}

// DeleteObject also succeeds when the key is already absent.
func (s *Storage) DeleteObject(
	ctx context.Context, sc backend.Scope, bucket resource.BucketName, key resource.ObjectKey,
) error {
	_, _, err := s.call(ctx, sc, http.MethodDelete, "/"+bucket.String()+"/"+key.String(), nil, nil, nil)
	return err
}

// ListObjects uses V2 with a reversible key cursor, preserving backend paging.
func (s *Storage) ListObjects(
	ctx context.Context, sc backend.Scope, q resource.ObjectQuery,
) (resource.ObjectListing, error) {
	q, err := q.Normalize()
	if err != nil {
		return resource.ObjectListing{}, err
	}
	query := url.Values{
		"list-type": {"2"}, "prefix": {q.Prefix}, "delimiter": {q.Delimiter},
		"max-keys": {strconv.Itoa(q.MaxKeys)}, "start-after": {q.StartAfter},
	}
	if q.Token != "" {
		query.Del("list-type")
		query.Del("start-after")
		query.Set("marker", q.Token)
	}
	data, _, err := s.call(ctx, sc, http.MethodGet, "/"+q.Bucket.String(), query, nil, nil)
	if err != nil {
		return resource.ObjectListing{}, err
	}
	var doc struct {
		XMLName     xml.Name `xml:"ListBucketResult"`
		IsTruncated bool
		Contents    []struct {
			Key, ETag, LastModified string
			Size                    int64
		}
		Prefixes []string `xml:"CommonPrefixes>Prefix"`
	}
	if decodeXML(data, &doc) != nil {
		return resource.ObjectListing{}, unavailable()
	}
	out := resource.ObjectListing{CommonPrefixes: doc.Prefixes}
	var last string
	for _, o := range doc.Contents {
		key, err := resource.Parse[resource.ObjectKey](o.Key)
		if err != nil || o.Size < 0 {
			return resource.ObjectListing{}, unavailable()
		}
		out.Objects = append(out.Objects, resource.Object{
			Bucket: q.Bucket, Key: key, OwnerID: sc.Account,
			ETag: o.ETag, Size: o.Size, LastModified: o.LastModified,
		})
		last = max(last, o.Key)
	}
	for _, p := range doc.Prefixes {
		last = max(last, p)
	}
	if doc.IsTruncated {
		if last == "" {
			return resource.ObjectListing{}, unavailable()
		}
		out.NextToken = last
	}
	return out, nil
}
