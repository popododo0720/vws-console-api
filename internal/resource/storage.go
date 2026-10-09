package resource

// MaxObjectBytes is the largest object body this process will accept.
// Larger objects belong on a path that does not buffer them here.
const MaxObjectBytes = 5 << 20

// Bucket is an object container.
type Bucket struct {
	Name         BucketName `json:"name"`
	OwnerID      AccountID  `json:"ownerId"`
	CreationDate string     `json:"creationDate"`
}

// Owner returns the account that owns the bucket.
func (b Bucket) Owner() AccountID { return b.OwnerID }

// Identity returns the bucket name.
func (b Bucket) Identity() string { return b.Name.String() }

// Object is the metadata of one stored object. The body is a stream beside it.
type Object struct {
	Bucket      BucketName `json:"bucket"`
	Key         ObjectKey  `json:"key"`
	OwnerID     AccountID  `json:"ownerId"`
	Size        int64      `json:"size"`
	ETag        string     `json:"etag"`
	ContentType string     `json:"contentType,omitempty"`
}

// Owner returns the account that owns the object.
func (o Object) Owner() AccountID { return o.OwnerID }

// Identity returns bucket and key.
func (o Object) Identity() string { return o.Bucket.String() + "/" + o.Key.String() }

// BucketQuery lists buckets.
type BucketQuery struct {
	Page PageRequest `json:"page,omitempty"`
}

// Normalize canonicalizes the page.
func (q BucketQuery) Normalize() (BucketQuery, error) {
	page, err := q.Page.Normalize()
	if err != nil {
		return BucketQuery{}, err
	}
	q.Page = page
	return q, nil
}

// PutObjectRequest is the metadata of an upload. The body is passed beside it
// so the fingerprint does not depend on buffering the bytes twice.
type PutObjectRequest struct {
	Bucket      BucketName `json:"bucket"`
	Key         ObjectKey  `json:"key"`
	ContentType string     `json:"contentType,omitempty"`
	Size        int64      `json:"size"`
}

// Normalize checks the metadata. Size is the declared length. A negative size
// means the length is unknown and the backend must measure the stream.
func (r PutObjectRequest) Normalize() (PutObjectRequest, error) {
	if r.Bucket.IsZero() {
		return PutObjectRequest{}, Invalid("bucket", "required")
	}
	if r.Key.IsZero() {
		return PutObjectRequest{}, Invalid("key", "required")
	}
	if r.Size < -1 || r.Size > MaxObjectBytes {
		return PutObjectRequest{}, Exhausted("object exceeds 5 MiB")
	}
	if len(r.ContentType) > 128 || hasControl(r.ContentType) {
		return PutObjectRequest{}, Invalid("contentType", "malformed")
	}
	return r, nil
}

// GetObjectRequest selects one object.
type GetObjectRequest struct {
	Bucket BucketName `json:"bucket"`
	Key    ObjectKey  `json:"key"`
}

// Normalize checks the names.
func (r GetObjectRequest) Normalize() (GetObjectRequest, error) {
	if r.Bucket.IsZero() {
		return GetObjectRequest{}, Invalid("bucket", "required")
	}
	if r.Key.IsZero() {
		return GetObjectRequest{}, Invalid("key", "required")
	}
	return r, nil
}
