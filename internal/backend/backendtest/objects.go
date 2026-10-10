package backendtest

import (
	"context"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func exerciseObjectList(ctx context.Context, t *testing.T, set backend.Set, account, other resource.AccountID) {
	t.Helper()
	bucket, err := resource.Parse[resource.BucketName]("list-logs")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := set.Storage.CreateBucket(ctx, backend.Scope{Account: account}, bucket); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"a.txt", "b/c.txt", "b/d.txt", "c.txt"} {
		putKey(ctx, t, set, account, bucket, key)
	}
	page, err := set.Storage.ListObjects(ctx, backend.Scope{Account: account}, resource.ObjectQuery{
		Bucket: bucket, Delimiter: "/", MaxKeys: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if keysOf(page.Objects) != "a.txt,c.txt" || page.NextToken != "" {
		t.Fatalf("objects %+v", page)
	}
	if len(page.CommonPrefixes) != 1 || page.CommonPrefixes[0] != "b/" {
		t.Fatalf("prefixes %+v", page.CommonPrefixes)
	}
	first, err := set.Storage.ListObjects(ctx, backend.Scope{Account: account}, resource.ObjectQuery{
		Bucket: bucket, Delimiter: "/", MaxKeys: 1,
	})
	if err != nil || first.NextToken != "a.txt" || keysOf(first.Objects) != "a.txt" {
		t.Fatalf("first %v %+v", err, first)
	}
	if err := set.Storage.DeleteObject(ctx, backend.Scope{Account: account}, bucket, mustKey(t, "a.txt")); err != nil {
		t.Fatal(err)
	}
	second, err := set.Storage.ListObjects(ctx, backend.Scope{Account: account}, resource.ObjectQuery{
		Bucket: bucket, Delimiter: "/", MaxKeys: 1, Token: first.NextToken,
	})
	if err != nil || second.NextToken != "b/" || len(second.CommonPrefixes) != 1 {
		t.Fatalf("after delete %v %+v", err, second)
	}
	inside, err := set.Storage.ListObjects(ctx, backend.Scope{Account: account}, resource.ObjectQuery{
		Bucket: bucket, Delimiter: "/", MaxKeys: 10, StartAfter: "b/c.txt",
	})
	if err != nil || keysOf(inside.Objects) != "c.txt" || len(inside.CommonPrefixes) != 1 || inside.CommonPrefixes[0] != "b/" {
		t.Fatalf("start-after %v %+v", err, inside)
	}
	if _, err := set.Storage.ListObjects(ctx, backend.Scope{Account: account}, resource.ObjectQuery{
		Bucket: bucket, MaxKeys: 10, Token: "bad\ntoken",
	}); resource.CodeOf(err) != resource.CodeInvalidArgument {
		t.Fatalf("malformed token %v", err)
	}
	missing, err := resource.Parse[resource.BucketName]("missing-logs")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := set.Storage.ListObjects(ctx, backend.Scope{Account: account}, resource.ObjectQuery{
		Bucket: missing, MaxKeys: 10,
	}); resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("missing bucket %v", err)
	}
	if _, err := set.Storage.ListObjects(ctx, backend.Scope{Account: other}, resource.ObjectQuery{
		Bucket: bucket, MaxKeys: 10,
	}); resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("other account %v", err)
	}
}

func mustKey(t *testing.T, key string) resource.ObjectKey {
	t.Helper()
	parsed, err := resource.Parse[resource.ObjectKey](key)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func putKey(ctx context.Context, t *testing.T, set backend.Set, account resource.AccountID, bucket resource.BucketName, key string) {
	t.Helper()
	body := "x"
	if _, err := set.Storage.PutObject(ctx, backend.Scope{Account: account}, resource.PutObjectRequest{
		Bucket: bucket, Key: mustKey(t, key), Size: int64(len(body)),
	}, strings.NewReader(body)); err != nil {
		t.Fatal(err)
	}
}

func keysOf(items []resource.Object) string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, item.Key.String())
	}
	return strings.Join(out, ",")
}
