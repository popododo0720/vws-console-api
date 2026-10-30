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
VWS_CONSOLE_TOKEN=dev-token VWS_ACCESS_KEY=AKIDEXAMPLE VWS_SECRET_KEY=secret \
go run ./cmd/vws-console-api -backend=fake \
  -console-addr=127.0.0.1:8080 \
  -ec2-addr=127.0.0.1:8081 \
  -s3-addr=127.0.0.1:8082 \
  -account=123456789012
```

`-backend=grpc` dials `-compute-addr`, `-storage-addr`, and `-network-addr`.

### Credentials

| Credential | Environment | File (Secret mount) | Deprecated flag |
| --- | --- | --- | --- |
| console bearer token | `VWS_CONSOLE_TOKEN` | `VWS_CONSOLE_TOKEN_FILE` | `-console-token` |
| root access key id | `VWS_ACCESS_KEY` | `VWS_ACCESS_KEY_FILE` | `-access-key` |
| root secret access key | `VWS_SECRET_KEY` | `VWS_SECRET_KEY_FILE` | `-secret` |

Each is read from the flag, then the `_FILE` path, then the variable. A flag
puts the value in the process arguments (`ps`, `/proc/<pid>/cmdline`), so it is
kept only for compatibility and logs a deprecation warning that names the flag,
never the value. Setting both `X_FILE` and `X` is an error, as is an empty or
unreadable file; one trailing newline in a file is dropped, like
`-root-password-file`. With `-backend=grpc` every credential must be given; the
defaults (`dev-token`, `AKIDEXAMPLE`, `secret`) are public development values
and are refused against real backends.
The fake backend is in-memory and is gone when the process exits.

`-ops-addr` (default `127.0.0.1:8083`, empty disables it) serves `GET /healthz`
(the process is up), `GET /readyz` (200 while the surfaces serve, 503 once
shutdown starts), and `GET /metrics` in the Prometheus text format. Every
series is prefixed `vws_console_api_`: `http_requests_total{surface,code}` and
`http_request_duration_seconds_sum`/`_count{surface}`. These live on their own
listener so no path collides with a bucket name or a console route.

### Observability

The process calls `obs.Setup` from vws-lib once at start and defers its
shutdown. With `OTEL_EXPORTER_OTLP_ENDPOINT` empty (the default) it exports
nothing and keeps the JSON log on stdout. Every inbound HTTP request gets a
server span, and every compute, storage, network, and IAM gRPC call carries
the W3C `traceparent` and the `x-request-id` metadata. Errors go through
`report.Error` and `report.Panic` only; the service does not import Sentry.

| Variable | Meaning | Default |
| --- | --- | --- |
| `OTEL_SERVICE_NAME` | Service name in traces and metrics | `console-api` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP collector; empty exports nothing | empty |
| `OTEL_EXPORTER_OTLP_PROTOCOL` | `grpc` or `http/protobuf` | `grpc` |
| `OTEL_EXPORTER_OTLP_HEADERS` | Auth headers for the collector | none |
| `OTEL_TRACES_SAMPLER`, `OTEL_TRACES_SAMPLER_ARG` | Sampling and ratio | `parentbased_traceidratio`, `0.1` |
| `OTEL_RESOURCE_ATTRIBUTES` | Extra resource attributes | none |
| `OTEL_TRACES_EXPORTER`, `OTEL_METRICS_EXPORTER`, `OTEL_LOGS_EXPORTER` | `otlp` or `none` | `otlp` when an endpoint is set |
| `SENTRY_DSN` | Sends errors to Sentry when set | empty |
| `SENTRY_ENVIRONMENT`, `SENTRY_RELEASE`, `SENTRY_SAMPLE_RATE` | Sentry tags and sample rate | derived, `1.0` |
| `VWS_LOG_LEVEL` | `debug`, `info`, `warn`, or `error` | `info` |
| `VWS_LOG_FORMAT` | `json` or `text` | `json` |
| `VWS_HEALTH_ADDR` | Serves `GET /healthz` and `GET /readyz` | empty, off |

`VWS_HEALTH_ADDR` is separate from `-ops-addr`; the chart sets it. Its
`/healthz` checks no dependency, and `/readyz` fails after SIGTERM. Neither
probe checks the telemetry backend. The metrics `vws.http.server.*`,
`vws.aws.errors{action,aws_code}`, and `vws.rpc.client.duration` go to the
OTLP exporter; `-ops-addr` keeps serving the process's Prometheus text series.

IAM and STS Query share `-iam-addr` (default `127.0.0.1:8084`). The service in
the signature's credential scope (`iam` or `sts`, region `vws-1`) picks the API:
IAM `2010-05-08`, STS `2011-06-15`, with AWS's XML and error codes. Every
action except `GetCallerIdentity` (as in AWS) is authorized as `iam:<Action>`
or `sts:<Action>`; every request must be signed. `-iam=static` (the
default) serves only `GetCallerIdentity` for the `-access-key` root key.
`-iam=fake` adds users, groups, roles, managed and inline policies, access keys
and `AssumeRole` in memory, lost on restart. The root key keeps working in every mode, and keys created
there also sign EC2 and S3 calls. `GetCallerIdentity` answers `Arn` in the `aws`
partition, as AWS does; IAM resource ARNs and `AssumeRole`'s role ARN still use
`arn:vws` (#430).

`-iam=grpc -iam-endpoint <host:port>` hands every other key to vws-iam
(vws-proto v0.3.0, `vws.iam.v1`). `Authenticate` gets the canonical request,
string to sign, signature and client address (`source_ip`), never a secret;
`Authorize` gets the full principal vws-iam returned (it rechecks unique id
and resource), the resource ARNs and the condition context, and only
`DECISION_ALLOW` allows; an error denies. Console sign-in (`Login`,
`ValidateSession`, `Logout`) goes to vws-iam too, with the client address the
console resolved (see `-trusted-proxies`); the root user still signs in
against `-root-password-file` locally. A bad password, unknown user or missing
MFA code is the same `401` as in the other modes, `RESOURCE_EXHAUSTED` from
vws-iam is `429`, and `UNAVAILABLE` or a transport failure is `503` with
`Retry-After`. A sign-in vws-iam marks `password_reset_required` is refused
(`403`) and its session revoked, because the console has no password-change
flow yet. STS `AssumeRole` sends the caller in the request's `authentication`
field: the caller's own SigV4 request, or its console session token; nothing
goes in gRPC metadata. The static root key cannot assume a role (as in AWS).
Each call has a 5 s timeout, or the request's deadline if earlier;
`Authenticate`, `Authorize`, `ValidateSession` and `Logout` retry `UNAVAILABLE`
up to 3 times with doubling backoff; `Login` and `AssumeRole` are never
retried. User and group management (`CreateUser`, `GetUser`, `ListUsers`,
`UpdateUser`, `DeleteUser`, `CreateGroup`, `GetGroup`, `ListGroups`,
`UpdateGroup`, `DeleteGroup`, `AddUserToGroup`, `RemoveUserFromGroup`,
`ListGroupsForUser`) goes to `UserService` and `GroupService`: every change
carries a `request_id`, and updates and deletes the etag they read, so a retry
of `UNAVAILABLE` (up to 3 times) cannot apply a change twice; a vws-iam that
stays down is `503`. A change acts only on the user or group at the ARN the
request was authorized on: one that moved in between is `409
ConcurrentModification`, and nothing is written (on both backends). Renaming a user or group (`NewUserName`,
`NewGroupName`) is `InvalidAction`, because vws-iam cannot rename.
`CreateAccessKey`, `ListAccessKeys`, `UpdateAccessKey` and `DeleteAccessKey`
go to `AccessKeyService`, for the user at the authorized ARN only. The secret
access key is in the `CreateAccessKey` response and nowhere else: console-api
never logs, traces or keeps it. `CreateAccessKey` is never retried, because
vws-iam does not replay it and a retry would create a second key; a third key
for a user is `LimitExceeded`. `UpdateAccessKey` sets `Active` or `Inactive`
through the `spec.state` mask, carries a `request_id`, is retried, and
sends the authorized ARN as `expected_user_arn`, which vws-iam checks in the
same transaction as the write, so a user that moved in between is `409
ConcurrentModification` and the key is unchanged (the user is also read again
after the call); an inactive key stops authenticating.
`DeleteAccessKey` carries a `request_id`, is retried, and sends
`expected_user_arn` the same way, so a moved user keeps the key.
The user and group policy actions (`Attach`, `Detach`, `ListAttached`, `Put`,
`Get`, `Delete` and `List` for `User` and `Group` policies) write the
`attached_policies` or `inline_policies` field of the user or group under the
etag they read, with a `request_id`, and read again when another writer won,
for the entity at the authorized ARN only. A user or group holds at most 10
managed policies, and its inline documents at most 2,048 (user) or 5,120
(group) characters without white space. vws-iam accepts inline policy names
of at most 64 characters, so a longer one, which AWS allows, is
`ValidationError`. Policy documents never reach a log or a span. `GetRole`,
`UpdateRole` and `UpdateRoleDescription` go to `RoleService`. IAM
management actions that are not mapped to vws-iam yet (among them the role
policy and login profile actions) answer `InvalidAction` in this mode.

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

Console sign-in needs `-iam fake` or `-iam grpc`. With the default
`-iam static` it is off: the console takes only the bearer `-console-token`,
`POST /api/v1/auth/login` and `POST /api/v1/auth/logout` answer `501`
`{"error":{"code":"Unimplemented","message":"console sign-in requires -iam fake or grpc"}}`,
session cookies are ignored, `-root-password-file` has no effect, and the
process logs a `WARN` at start saying so. `GET /api/v1/auth/session` always
carries `loginEnabled` so the UI can tell the modes apart:

| mode | no credentials | bearer token | session cookie |
| --- | --- | --- | --- |
| `-iam static` | `200` `{"loginEnabled":false}` | `200` caller + `"loginEnabled":false` | ignored: as no credentials |
| `-iam fake` / `grpc` | `401` (show the sign-in page) | `200` caller + `"loginEnabled":true` | `200` caller, `expiresAt`, `"loginEnabled":true` |

In static mode the session route needs no credentials because the answer
names nobody and there is nothing to sign in to; a bad bearer token is still
`401`. The login response carries `"loginEnabled":true` too.

With sign-in on: `POST /api/v1/auth/login` with
`{"account","userName","password"}` (an IAM user's `CreateLoginProfile`
password, or `root` with the password in `-root-password-file`, mounted from a
Secret). It sets an HttpOnly, Secure, SameSite=Strict `vws_session` cookie
(12 hours) and a `vws_csrf` cookie; every request other than GET/HEAD on a
session must echo `vws_csrf` in `X-CSRF-Token`. Each console route is
authorized as the matching IAM action (`ec2:DescribeVpcs`, `ec2:CreateVpc`,
`s3:GetObject`, `vws:GetOperation`, ...), so a session only does what the
user's policies allow. Every failure is the same `401`. Abuse limits: five
wrong passwords in a row from one address lock that user from that address
only (1 minute, doubling per further failure up to 1 hour, logged as
`console sign-in locked out` without secrets), so nobody can lock root out
from elsewhere; each address gets 10 sign-in attempts, refilling one every
6 s (`429` with `Retry-After`); argon2id hashing runs in a bounded number of
slots and a sign-in that cannot get one within 200 ms is `503` with
`Retry-After`. Sign-in and every state-changing cookie request must be
`Content-Type: application/json` (else `415`) and carry an `Origin` that is
the console's own host or one listed in `-console-origins` (else `403`). The
one exception to the JSON rule is an object upload
(`PUT /api/v1/buckets/{name}/objects/{key}`), whose `Content-Type` is the
object's and is stored and returned as S3 does; it still needs the `Origin`
and `X-CSRF-Token` (else `403`). `GET /api/v1/auth/session` names
the caller; `POST /api/v1/auth/logout` ends the session. The bearer
`-console-token` still acts as the account root until it is retired.

### Behind a proxy: `-trusted-proxies`

Sign-in rate limits, per user+address lockout and the `source_ip` in sign-in
logs key on the client address. By default that is the TCP peer
(`RemoteAddr`) and `X-Forwarded-For` is ignored. Behind an L7 proxy or
ingress every user would then share the proxy's address, making the limit
global and letting anyone lock root out, so list the proxies' CIDRs:

    -trusted-proxies 10.0.0.0/8,fd00::/8

Only when the TCP peer is inside one of them is `X-Forwarded-For` read (all
header lines, in order), walked right to left, and the first address that is
not a trusted proxy taken as the client. Entries left of it are written by
the client and never used, so a forged leftmost entry changes nothing, and a
request that reaches the console directly from an untrusted address cannot
set its own client address at all. If every entry is trusted, the leftmost
is used (an internal client); if the header is missing or an entry walked is
not an IP, the TCP peer is used. List only your proxy hops (e.g. the ingress
controller pods' range), make the proxy append to `X-Forwarded-For`, and do
not expose the console port past the proxy. A bad CIDR (or one with host
bits set) stops startup. `Origin` checks compare against the `Host` header
and `-console-origins`, not the client address, so they are unaffected.

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

## Error status by listener

The console listener is this service's JSON API, not an AWS protocol. The web
console reads HTTP 404 with the body code `NotFound` as a missing resource, so
the console keeps 404. A 400 would surface the same absence as an error.

The AWS protocol listeners use the status on the AWS page for that API.

| Listener | Missing resource | Status | AWS page |
| --- | --- | --- | --- |
| EC2 Query | `InvalidAMIID.NotFound` and the other `*.NotFound` codes | 400 | [EC2 error codes](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/errors-overview.html) |
| S3 | `NoSuchBucket`, `NoSuchKey` | 404 | [S3 error responses](https://docs.aws.amazon.com/AmazonS3/latest/developerguide/ErrorResponses.html) |
| IAM | `NoSuchEntity` | 404 | [DeleteUser errors](https://docs.aws.amazon.com/IAM/latest/APIReference/API_DeleteUser.html) |

EC2 client errors, including `InvalidAction`, are a 400-series response.
EC2 server errors, including `RequestLimitExceeded`, are a 500-series
response, and this listener answers `RequestLimitExceeded` as 503. S3
`EntityTooLarge` is 400. Each listener's error test pins the full table.

## Resource API module

The gRPC client imports `github.com/popododo0720/vws-proto` at a release tag
(`go.mod` pins it; today `v0.8.0`). The repo is public, so `go mod download`
fetches it through the default module proxy with no token or `GOPRIVATE`. To
take a new proto release, run `go get github.com/popododo0720/vws-proto@vX.Y.Z`
and `go mod tidy`. Never copy or `replace` the module.

## Layout

See `AGENTS.md` for the rule table, the branch and commit rules, and when to
use pstack (`architect`, `interrogate`, `correct`).

```sh
go test -race ./...
golangci-lint run
```
