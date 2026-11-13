# AWS forwarding proxy

`cmd/vws-aws-proxy` accepts only local, already authenticated and authorized
requests. Its unix socket is mode 0700; run the global API under the same user
and place the socket in a private directory. The API must replace all client
`X-Vws-*` headers with its verified VWS project, principal, target region and service.
EC2 retains its unambiguous Query action list and 1 MiB body limit. Other
services forward their method, path, query and body with a 4 MiB limit.
Requests have a 30-second deadline. Transient
upstream failures get at most three attempts with 100/200 ms backoff.

Flags: `-socket`, `-global-config`, `-accounts`, `-projects`, `-sts-endpoint`,
`-sts-region`, `-ec2-endpoint`, `-aws-endpoint`.
AssumeRole is signed for `-sts-region` (default `us-east-1`, the global STS
endpoint's region), never for the EC2 region of the request; a regional STS
endpoint needs its own region here.
Endpoints must use HTTPS, except numeric loopback addresses for offline tests.
The EC2 endpoint can contain `{region}`. Redirects are returned, never followed.
The required `-aws-endpoint` supplies the endpoint for other services, for
example `https://{service}.{region}.<operator-supplied-dns-suffix>`. Replace
the suffix with the actual service DNS suffix before starting the process.
`{service}` is the signing name and `{region}` is the verified target region;
an endpoint whose DNS prefix differs from its signing name needs an appropriate
operator-selected template. No endpoint is inferred from client headers.
For S3, an inbound `bucket.s3.<suffix>` host retains the bucket prefix on the
target host (including dotted bucket names); path-style paths stay unchanged.
The router preserves the verified S3 Host over its fixed Unix socket and
discards client-supplied `X-Vws-*` routing metadata. It derives virtual-host
IAM actions from the same bucket and key that the proxy forwards.

PutObject, CopyObject and CreateMultipartUpload additionally authorize upload
ACL/grant headers as `s3:PutObjectAcl`, tagging headers as `s3:PutObjectTagging`,
Object Lock mode/retain-until-date as `s3:PutObjectRetention`, and legal-hold
as `s3:PutObjectLegalHold`. Empty, repeated or unknown grant/lock headers and
permission headers on other operations are refused before forwarding.
The mapping follows the S3 required permissions table:
https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-policy-actions.html

Proxy principals must contain 1 to 2048 ASCII characters from
`A-Za-z0-9_+=,.@:/-`. This uses the STS RoleSessionName character set plus
the colon and slash delimiters of IAM/STS principal ARNs; the principal is
hashed into the generated session name, whose existing 64-character bound
is unchanged. Invalid or repeated principals reach no STS call, including
on the private account diagnostic route.
https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html#API_AssumeRole_RequestParameters

Use `-global-config /etc/vws/global.yaml` to read the live admin registry over
the bootstrap's IAM etcd TLS connection. Project remaps and account changes
take effect on the next request without restart. The proxy does not need
the registry KEK: forwarding ExternalId remains a systemd credential.

For offline snapshot mode, omit `-global-config` and supply both `-accounts`
and `-projects`. Mixing live bootstrap and snapshots is refused.
`-accounts` is a JSON snapshot exported from admin registrations:

```json
[{"awsAccountId":"123456789012","roleArn":"arn:aws:iam::123456789012:role/inventory","allowedRegions":["us-east-1"]}]
```

`-projects` is a JSON snapshot of admin project mappings:

```json
[{"project":"111111111111","pools":[],"awsAccounts":["123456789012"]}]
```

Restart after replacing either snapshot. The proxy core consumes only `Accounts`;
`RegistryAccounts`
reads `Registry.Projects()` and resolves role ARN and allowed regions through
`Registry.AWSAccounts()` on each request. Only one mapped account may allow
the target region. No mapping, no match, unreadable registrations or multiple
matches return `AccessDenied` without STS or EC2 calls. Account ordering does
not break ties. The role ARN must belong to the selected AWS account.
Neither registration nor source credentials are accepted from request metadata.

Supply these files using systemd `LoadCredential=` and its
`CREDENTIALS_DIRECTORY`, readable only by the proxy process:

- `aws-source`: JSON with `AccessKey`, `Secret`, and optional `SessionToken`.
- `aws-external-id-<12-digit-account>`: that account's nonempty ExternalId.

The executable fails before listening if source credentials are missing,
malformed, or example/default keys. AWS environment variables and shared profiles
are never read. This increment uses the systemd-file source option; it does not
implement an instance role provider. Restart for source key rotation. ExternalId
is read for each request and changes invalidate cached sessions. Registry-backed,
encrypted ExternalId storage for forwarding remains for later.

Sessions are held only in memory until five minutes before expiry. Cache keys
include the selected AWS account, role, ExternalId and principal, isolated by
project and mapping revision. Observing a changed mapping drops that project's
older sessions, including when unmapped; mapping away and back cannot revive
a prior session. An unreadable project mapping denies forwarding while retaining
cached sessions until its revision can be read again. Each STS session name
records the VWS project and principal hash. The cache is bounded to 1024 entries;
restart drops it.
All outbound errors exposed to callers are fixed messages, never response bodies,
credential fields or transport error strings. The command uses vws-lib telemetry
and HTTP server spans/metrics; sanitized STS decoding failures use `report.Error`.

Forwarding replaces Authorization, X-Amz-Date and the user's session token with
the assumed session's signature and token. S3 always receives a recomputed
X-Amz-Content-Sha256; other services receive it only when it was present.
Other x-amz headers, Content-Type and Content-Length are kept and signed,
along with supported content, cache and conditional headers. Hop-by-hop
headers and Connection-nominated headers are removed; local identity metadata,
cookies and caller credentials never reach the origin.

STREAMING-AWS4-HMAC-SHA256-PAYLOAD bodies are unwrapped and signed as a single
payload. Both wire bytes and decoded bytes must fit the 4 MiB bound. The
aws-chunked encoding and X-Amz-Decoded-Content-Length are removed, other
content encodings remain and Content-Length reflects the decoded bytes.
Malformed sizes, signatures, truncation and excess bytes return the fixed
InvalidParameterValue error before STS or origin calls. This private socket
accepts only requests already authenticated and authorized by the global API;
unwrapping does not authenticate the user's chunk signatures.

Presigned query authentication, UNSIGNED-PAYLOAD and SigV4a (including
X-Amz-Region-Set) return UnauthorizedOperation before any outbound call.
The origin's status, end-to-end headers and body bytes pass through unchanged,
including arn:aws: strings and compressed payloads. Automatic response
decompression is disabled. Generic mutations are not retried after uncertain
transport errors or 5xx responses; throttling retains the bounded retry policy.

## Private account connection tests

`POST /internal/v1/aws-accounts/test` on the private Unix socket takes JSON
`awsAccountId`, `roleArn` and `externalId`. The trusted local caller supplies
`X-Vws-Account` matching the body, `X-Vws-Principal`, and
`X-Vws-Target-Service: sts`. Content-Type must be application/json; queries,
unknown or repeated fields, invalid metadata and bodies over 16 KiB are refused.
This route is not registered on any public listener.

Each test runs uncached AssumeRole then GetCallerIdentity against the configured
STS endpoint, using forwarding's session duration, principal-derived session
name and signing region. The 10-second sequence never calls the EC2 origin,
reads or fills the credential cache, or writes registry state. Source and
session credentials stay inside the proxy.

The response is no-store JSON with ordered `assume_role` and
`get_caller_identity` steps. Each has `name`, `result` and a fixed `message`;
results are PASS, FAIL or SKIPPED. Failure skips later steps. A diagnostic
requires one complete XML document with the expected root and one result,
usable credentials, and exactly one 12-digit identity Account equal to the
requested account. Unexpected XML is an unusable-response failure.
Expected diagnostic denials do not generate error events; real faults and
forwarding retain error reporting. ExternalId never appears in URLs, logs,
error messages or responses.

Inventory still reads its ExternalId from the interim credential file; a
diagnostic tests only the supplied request-scoped value.

## Account connection tests

The console's `-aws-proxy-socket` defaults to `/run/vws/aws-proxy.sock` and
requires an absolute, clean socket path of at most 107 bytes. Root callers can POST a complete account
form to `/api/v1/admin/aws-accounts/test`, or an empty JSON object to
`/api/v1/admin/aws-accounts/{id}/test` to test the saved registration.
Both require the global KEK, cookie CSRF, and the admin write limiter.
Responses have `Cache-Control: no-store` and ordered `assume_role` and
`get_caller_identity` steps with PASS, FAIL or SKIPPED results.

The console opens the saved account-bound seal and sends only the account id,
role ARN and request-scoped ExternalId as JSON to the private socket's
`POST /internal/v1/aws-accounts/test`. Headers supply the authenticated
principal, matching account, request id and target service `sts`.
The proxy accepts at most 16 KiB, rejects queries, unknown or repeated fields
and invalid metadata, and performs fresh AssumeRole then GetCallerIdentity
against its configured STS endpoint. It uses forwarding's session duration
and principal-derived session name. The identity must match the requested
account. Failure skips later steps; no test reads or fills the session cache,
calls the EC2 origin, or writes the registry.

Source and session credentials stay in the proxy. ExternalId is never a URL,
header, log, audit field, error or response value. Only fixed diagnostic
messages cross back to the console. Proxy, client and console deadlines are
10, 12 and 15 seconds. A proxy outage or older proxy becomes FAIL/SKIPPED;
a saved record that cannot be opened asks the operator to save it again.

A saved PASS proves the current sealed registry registration. Inventory
forwarding still uses the credential-file ExternalId. Snapshot mode also needs
the startup registrations described above. Operators must keep these inputs
consistent; migrating forwarding to sealed registry credentials is outside
the connection-test implementation.
