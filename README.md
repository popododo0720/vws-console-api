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
With `-backend=grpc`, `-console-token`, `-access-key`, and `-secret` must be
given explicitly. Their defaults (`dev-token`, `AKIDEXAMPLE`, `secret`) are
public development values and are refused against real backends.
The fake backend is in-memory and is gone when the process exits.

`-ops-addr` (default `127.0.0.1:8083`, empty disables it) serves `GET /healthz`
(the process is up), `GET /readyz` (200 while the surfaces serve, 503 once
shutdown starts), and `GET /metrics` in the Prometheus text format. Every
series is prefixed `vws_console_api_`: `http_requests_total{surface,code}` and
`http_request_duration_seconds_sum`/`_count{surface}`. These live on their own
listener so no path collides with a bucket name or a console route.

IAM and STS Query share `-iam-addr` (default `127.0.0.1:8084`). The service in
the signature's credential scope (`iam` or `sts`, region `vws-1`) picks the API:
IAM `2010-05-08`, STS `2011-06-15`, with AWS's XML and error codes. Every
action except `GetCallerIdentity` (as in AWS) is authorized as `iam:<Action>`
or `sts:<Action>`; every request must be signed. `-iam=static` (the
default) serves only `GetCallerIdentity` for the `-access-key` root key.
`-iam=fake` adds users, groups, roles, managed and inline policies, access keys
and `AssumeRole` in memory, lost on restart, until the vws-iam client lands
(vws-proto#24). The root key keeps working in both modes, and keys created
there also sign EC2 and S3 calls.

```sh
aws --endpoint-url http://127.0.0.1:8084 --region vws-1 iam create-user --user-name bob
aws --endpoint-url http://127.0.0.1:8084 --region vws-1 sts get-caller-identity
```

Console:

```http
POST /api/v1/instances
Authorization: Bearer dev-token
Idempotency-Key: launch-web-1
Content-Type: application/json

{"imageId":"ami-0123456789abcdef0","instanceType":"vws.small","subnetId":"subnet-0123456789abcdef0","count":1}
```

Console sign-in: `POST /api/v1/auth/login` with
`{"account","userName","password"}` (an IAM user's `CreateLoginProfile`
password, or `root` with the password in `-root-password-file`, mounted from a
Secret). It sets an HttpOnly, Secure, SameSite=Strict `vws_session` cookie
(12 hours) and a `vws_csrf` cookie; every request other than GET/HEAD on a
session must echo `vws_csrf` in `X-CSRF-Token`. Each console route is
authorized as the matching IAM action (`ec2:DescribeVpcs`, `ec2:CreateVpc`,
`s3:GetObject`, `vws:GetOperation`, ...), so a session only does what the
user's policies allow. Five wrong passwords in a row lock the user for 15
minutes, and every failure is the same `401`. `GET /api/v1/auth/session` names
the caller; `POST /api/v1/auth/logout` ends the session. The bearer
`-console-token` still acts as the account root until it is retired.

Console sign-in limits for now:

- **Run one replica.** Console sessions (and `-iam=fake` users) live in the
  process's memory, so a second replica would not know a session the first
  one issued, and a restart signs everyone out. Keep `replicas: 1` until
  vws-iam holds sessions.
- **No MFA yet.** Users have no MFA devices until vws-iam#6, so a login that
  sends `mfaCode` fails.
- **No forced password change.** `CreateLoginProfile`/`UpdateLoginProfile`
  reject `PasswordResetRequired=true` until a change-password flow exists.
- **`-console-token` stays** as the account root until vws-console signs in
  with cookies; it is removed after that switch.

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
This skeleton accepts object bodies up to 4 MiB. A larger body is not a quota
error.

## Resource API module

The gRPC client imports `github.com/popododo0720/vws-proto`. That module is
not public yet, so `go.mod` replaces it with `third_party/vws-proto` (a
snapshot of main `a1c6084`). When vws-proto is public, remove the replace and
require a tagged version.

## Layout

See `AGENTS.md` for the rule table, the branch and commit rules, and when to
use pstack (`architect`, `interrogate`, `correct`).

```sh
go test -race ./...
golangci-lint run
```
