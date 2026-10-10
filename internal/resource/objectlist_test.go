package resource

import "testing"

func TestObjectListGroupsByDelimiter(t *testing.T) {
	bucket := mustBucket(t, "logs")
	other := mustBucket(t, "other-logs")
	keys := []Object{
		obj(bucket, "a.txt"),
		obj(bucket, "b/c.txt"),
		obj(bucket, "b/d.txt"),
		obj(bucket, "c.txt"),
		obj(bucket, "a b/c"),
		obj(other, "secret"),
	}
	page, err := PageObjects(keys, ObjectQuery{Bucket: bucket, Delimiter: "/", MaxKeys: 1000})
	if err != nil {
		t.Fatal(err)
	}
	if page.NextToken != "" {
		t.Fatalf("full page %+v", page)
	}
	if got := names(page.Objects); got != "a.txt,c.txt" {
		t.Fatalf("objects %s", got)
	}
	if len(page.CommonPrefixes) != 2 || page.CommonPrefixes[0] != "a b/" || page.CommonPrefixes[1] != "b/" {
		t.Fatalf("prefixes %+v", page.CommonPrefixes)
	}

	under, err := PageObjects(keys, ObjectQuery{Bucket: bucket, Prefix: "b/", Delimiter: "/", MaxKeys: 1000})
	if err != nil {
		t.Fatal(err)
	}
	if names(under.Objects) != "b/c.txt,b/d.txt" || len(under.CommonPrefixes) != 0 {
		t.Fatalf("under %+v", under)
	}

	spaced, err := PageObjects(keys, ObjectQuery{Bucket: bucket, Prefix: "a b/", MaxKeys: 10})
	if err != nil {
		t.Fatal(err)
	}
	if names(spaced.Objects) != "a b/c" {
		t.Fatalf("space prefix %+v", spaced.Objects)
	}
}

func TestObjectListContinues(t *testing.T) {
	bucket := mustBucket(t, "logs")
	keys := []Object{obj(bucket, "a.txt"), obj(bucket, "b/c.txt"), obj(bucket, "b/d.txt"), obj(bucket, "c.txt")}
	first, err := PageObjects(keys, ObjectQuery{Bucket: bucket, Delimiter: "/", MaxKeys: 1})
	if err != nil {
		t.Fatal(err)
	}
	if names(first.Objects) != "a.txt" || first.NextToken != "a.txt" {
		t.Fatalf("first %+v", first)
	}
	withoutA := keys[1:]
	resumed, err := PageObjects(withoutA, ObjectQuery{Bucket: bucket, Delimiter: "/", MaxKeys: 1, Token: first.NextToken})
	if err != nil {
		t.Fatal(err)
	}
	if len(resumed.CommonPrefixes) != 1 || resumed.CommonPrefixes[0] != "b/" {
		t.Fatalf("deleted cursor %+v", resumed)
	}
	second, err := PageObjects(keys, ObjectQuery{Bucket: bucket, Delimiter: "/", MaxKeys: 1, Token: first.NextToken})
	if err != nil {
		t.Fatal(err)
	}
	if len(second.CommonPrefixes) != 1 || second.CommonPrefixes[0] != "b/" || second.NextToken != "b/" {
		t.Fatalf("second %+v", second)
	}
	third, err := PageObjects(keys, ObjectQuery{Bucket: bucket, Delimiter: "/", MaxKeys: 1, Token: second.NextToken})
	if err != nil {
		t.Fatal(err)
	}
	if third.NextToken != "" || names(third.Objects) != "c.txt" {
		t.Fatalf("third %+v", third)
	}
	inside, err := PageObjects(keys, ObjectQuery{Bucket: bucket, Delimiter: "/", MaxKeys: 10, StartAfter: "b/c.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if names(inside.Objects) != "c.txt" || len(inside.CommonPrefixes) != 1 || inside.CommonPrefixes[0] != "b/" {
		t.Fatalf("start-after inside group %+v", inside)
	}
	zero, err := PageObjects(keys, ObjectQuery{Bucket: bucket, Delimiter: "/", MaxKeys: 0})
	if err != nil {
		t.Fatal(err)
	}
	if zero.NextToken != "" || names(zero.Objects) != "a.txt,c.txt" || len(zero.CommonPrefixes) != 1 {
		t.Fatalf("default page %+v", zero)
	}
}

func TestObjectListRejectsUnknownToken(t *testing.T) {
	bucket := mustBucket(t, "logs")
	_, err := PageObjects(nil, ObjectQuery{Bucket: bucket, MaxKeys: 10, Token: "bad\ntoken"})
	if CodeOf(err) != CodeInvalidArgument {
		t.Fatalf("token %v", err)
	}
	_, err = PageObjects(nil, ObjectQuery{Bucket: bucket, MaxKeys: 10, Prefix: "has\nline"})
	if CodeOf(err) != CodeInvalidArgument {
		t.Fatalf("prefix %v", err)
	}
	_, err = PageObjects(nil, ObjectQuery{Bucket: bucket, MaxKeys: 1001})
	if CodeOf(err) != CodeInvalidArgument {
		t.Fatalf("max %v", err)
	}
}

func mustBucket(t *testing.T, name string) BucketName {
	t.Helper()
	bucket, err := Parse[BucketName](name)
	if err != nil {
		t.Fatal(err)
	}
	return bucket
}

func obj(bucket BucketName, key string) Object {
	parsed, err := Parse[ObjectKey](key)
	if err != nil {
		panic(err)
	}
	return Object{Bucket: bucket, Key: parsed}
}

func names(items []Object) string {
	out := ""
	for i, item := range items {
		if i > 0 {
			out += ","
		}
		out += item.Key.String()
	}
	return out
}
