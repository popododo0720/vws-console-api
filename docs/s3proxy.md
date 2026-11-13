# S3 origin storage

`internal/backend/s3proxy.New` implements `backend.Storage` against an
operator-selected S3-compatible origin, using path-style requests and an
explicit origin signing region. The caller's `Scope.Account` is the project.
The backend reads its current key from the admin registry on every call.
Both access key and secret are sealed under the registry KEK with project
and purpose binding. Registry records expose ciphertext only.

The operator creates RGW users; this package does not create users or hold
bucket/object state. Missing project keys are AccessDenied without any
origin request. Replies are bounded before parsing or returning object
bytes. GET retries transient failures at most three times with bounded
backoff under a ten-second call deadline. Mutations are sent once because
retrying an ambiguous conditional write or bucket creation changes its
answer. Redirects are refused.

This first part of #796 supplies the storage implementation and registry
contract. Binary flags, regionset assembly and an authorized admin write
API are deferred to the next part. Runtime defaults are unchanged.
`backendtest.S3` exercises the existing bucket/object groups through the
real S3 REST codec and signature verifier against in-memory origin storage.
