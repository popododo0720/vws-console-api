# vws-console-api

Web backend for VWS. One process serves the Next.js console, an EC2 Query
entry point, and a path-style object entry point. It does not store resources.
Compute, storage, and network live behind gRPC. A restart of this process
drops nothing, because the idempotency record and the operation live in the
service that owns the resource.

Long-running work returns an operation. The console polls it. Query clients
poll the resource state, which is the same lifecycle. Bucket and object calls
finish before the response.

The console JSON is the resource model. `instanceId`, `pending`, and `running`
are the same strings on the query surface.

## Run

```sh
go run ./cmd/vws-console-api -backend=fake \
  -console-addr=127.0.0.1:8080 \
  -ec2-addr=127.0.0.1:8081 \
  -s3-addr=127.0.0.1:8082 \
  -account=123456789012 \
  -console-token=dev-token \
  -access-key=AKIDEXAMPLE \
  -secret=secret
```

`-backend=grpc` dials `-compute-addr`, `-storage-addr`, and `-network-addr`.
The fake backend is in-memory and is gone when the process exits.

Console:

```http
POST /api/v1/instances
Authorization: Bearer dev-token
Idempotency-Key: launch-web-1
Content-Type: application/json

{"imageId":"ami-0123456789abcdef0","instanceType":"vws.small","subnetId":"subnet-0123456789abcdef0","count":1}
```

The subnet must already exist and belong to the caller. The response is `202`
with an `operation` and the instances. Poll `GET /api/v1/operations/{id}`.
`GET /api/v1/buckets/{name}/objects/{key}` returns the object metadata and the
body. Repeating the same idempotency key and the same body returns the same
operation and the same ids. A different body with the same key is rejected.

Query, signed with service `ec2`, region `vws-1`, version `2016-11-15`:

```text
Action=RunInstances&Version=2016-11-15&ImageId=ami-0123456789abcdef0&InstanceType=vws.small&SubnetId=subnet-0123456789abcdef0&MinCount=1&MaxCount=1&ClientToken=launch-web-1
```

`ClientToken` is required. `MinCount` and `MaxCount` must be equal. A parameter
this entry point does not apply is rejected. The same client token returns the
same instances. Object calls use path-style URLs on the object listener:
`PUT /build-logs`, `PUT /build-logs/a.txt`, `GET /build-logs/a.txt`.
Subresources such as `?tagging` and `X-Amz-Copy-Source` are refused, so they
cannot replace an object.

Header signatures are checked. Presigned query strings are refused.
This skeleton accepts object bodies up to 5 MiB. A larger body is not a quota
error.

## Layout

See `AGENTS.md` for the rule table, the branch and commit rules, and when to
use pstack (`architect`, `interrogate`, `correct`).

```sh
go test -race ./...
golangci-lint run
```
