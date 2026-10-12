package fake

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"io"
	"time"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

type storage struct{ w *World }

func (s storage) CreateBucket(ctx context.Context, sc backend.Scope, name resource.BucketName) (resource.Bucket, error) {
	if err := ctx.Err(); err != nil {
		return resource.Bucket{}, err
	}
	s.w.mu.Lock()
	defer s.w.mu.Unlock()
	if cur, ok := s.w.buck[name]; ok {
		if cur.OwnerID != sc.Account {
			return resource.Bucket{}, resource.AlreadyExists(resource.KindBucket, name.String())
		}
		return *cur, nil
	}
	b := &resource.Bucket{
		Name:         name,
		OwnerID:      sc.Account,
		CreationDate: s.w.now().UTC().Format(time.RFC3339),
	}
	s.w.buck[name] = b
	return *b, nil
}

func (s storage) GetBucket(ctx context.Context, sc backend.Scope, name resource.BucketName) (resource.Bucket, error) {
	if err := ctx.Err(); err != nil {
		return resource.Bucket{}, err
	}
	s.w.mu.Lock()
	defer s.w.mu.Unlock()
	b, ok := s.w.buck[name]
	if !ok || b.OwnerID != sc.Account {
		return resource.Bucket{}, resource.NotFound(resource.KindBucket, name.String())
	}
	return *b, nil
}

func (s storage) ListBuckets(ctx context.Context, sc backend.Scope, q resource.BucketQuery) (resource.Page[resource.Bucket], error) {
	if err := ctx.Err(); err != nil {
		return resource.Page[resource.Bucket]{}, err
	}
	s.w.mu.Lock()
	defer s.w.mu.Unlock()
	var items []resource.Bucket
	for _, b := range s.w.buck {
		if b.OwnerID == sc.Account {
			items = append(items, *b)
		}
	}
	sortBuckets(items)
	return page(items, q.Page)
}

func (s storage) DeleteBucket(ctx context.Context, sc backend.Scope, name resource.BucketName) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.w.mu.Lock()
	defer s.w.mu.Unlock()
	b, ok := s.w.buck[name]
	if !ok || b.OwnerID != sc.Account {
		return resource.NotFound(resource.KindBucket, name.String())
	}
	prefix := name.String() + "\x00"
	for key := range s.w.obj {
		if len(key) >= len(prefix) && key[:len(prefix)] == prefix {
			return resource.Conflict(resource.KindBucket, name.String(), "bucket is not empty")
		}
	}
	delete(s.w.buck, name)
	return nil
}

func (s storage) PutObject(ctx context.Context, sc backend.Scope, req resource.PutObjectRequest, body io.Reader) (resource.Object, error) {
	if err := ctx.Err(); err != nil {
		return resource.Object{}, err
	}
	buf, err := readLimited(body, resource.MaxObjectBytes)
	if err != nil {
		return resource.Object{}, err
	}
	if req.Size >= 0 && int64(len(buf)) != req.Size {
		return resource.Object{}, resource.Invalid("size", "body length does not match")
	}
	s.w.mu.Lock()
	defer s.w.mu.Unlock()
	b, ok := s.w.buck[req.Bucket]
	if !ok || b.OwnerID != sc.Account {
		return resource.Object{}, resource.NotFound(resource.KindBucket, req.Bucket.String())
	}
	sum := md5.Sum(buf)
	obj := &storedObject{
		meta: resource.Object{
			Bucket:       req.Bucket,
			Key:          req.Key,
			OwnerID:      sc.Account,
			Size:         int64(len(buf)),
			ETag:         `"` + hex.EncodeToString(sum[:]) + `"`,
			ContentType:  req.ContentType,
			LastModified: s.w.now().UTC().Format(time.RFC3339),
		},
		body: buf,
	}
	s.w.obj[objectKey(req.Bucket, req.Key)] = obj
	return obj.meta, nil
}

func (s storage) GetObject(ctx context.Context, sc backend.Scope, req resource.GetObjectRequest) (resource.Object, io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return resource.Object{}, nil, err
	}
	s.w.mu.Lock()
	defer s.w.mu.Unlock()
	obj, ok := s.w.obj[objectKey(req.Bucket, req.Key)]
	if !ok || obj.meta.OwnerID != sc.Account {
		return resource.Object{}, nil, resource.NotFound(resource.KindObject, req.Key.String())
	}
	if b, exists := s.w.buck[req.Bucket]; !exists || b.OwnerID != sc.Account {
		return resource.Object{}, nil, resource.NotFound(resource.KindBucket, req.Bucket.String())
	}
	body := append([]byte(nil), obj.body...)
	return obj.meta, io.NopCloser(bytes.NewReader(body)), nil
}

func (s storage) DeleteObject(ctx context.Context, sc backend.Scope, bucket resource.BucketName, key resource.ObjectKey) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.w.mu.Lock()
	defer s.w.mu.Unlock()
	b, ok := s.w.buck[bucket]
	if !ok || b.OwnerID != sc.Account {
		return resource.NotFound(resource.KindBucket, bucket.String())
	}
	delete(s.w.obj, objectKey(bucket, key))
	return nil
}

func (s storage) ListObjects(ctx context.Context, sc backend.Scope, q resource.ObjectQuery) (resource.ObjectListing, error) {
	if err := ctx.Err(); err != nil {
		return resource.ObjectListing{}, err
	}
	q, err := q.Normalize()
	if err != nil {
		return resource.ObjectListing{}, err
	}
	s.w.mu.Lock()
	b, ok := s.w.buck[q.Bucket]
	if !ok || b.OwnerID != sc.Account {
		s.w.mu.Unlock()
		return resource.ObjectListing{}, resource.NotFound(resource.KindBucket, q.Bucket.String())
	}
	keys := make([]resource.Object, 0, len(s.w.obj))
	for _, obj := range s.w.obj {
		if obj.meta.Bucket == q.Bucket && obj.meta.OwnerID == sc.Account {
			keys = append(keys, obj.meta)
		}
	}
	s.w.mu.Unlock()
	return resource.PageObjects(keys, q)
}

func objectKey(bucket resource.BucketName, key resource.ObjectKey) string {
	return bucket.String() + "\x00" + key.String()
}

func readLimited(r io.Reader, max int) ([]byte, error) {
	if r == nil {
		return []byte{}, nil
	}
	buf, err := io.ReadAll(io.LimitReader(r, int64(max)+1))
	if err != nil {
		return nil, resource.Internal(err)
	}
	if len(buf) > max {
		return nil, resource.TooLarge("object exceeds 4 MiB")
	}
	return buf, nil
}

func sortBuckets(items []resource.Bucket) {
	for i := 1; i < len(items); i++ {
		for j := i; j > 0 && items[j].Name.String() < items[j-1].Name.String(); j-- {
			items[j], items[j-1] = items[j-1], items[j]
		}
	}
}
