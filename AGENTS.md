# AGENTS.md

This repository is the web-only backend of VWS, a private cloud with an
AWS-shaped control plane. One stateless process serves three surfaces: the
console JSON API, an EC2 Query entry point, and an S3 REST entry point.
Compute, storage, and network state lives in internal services reached over
gRPC. This process keeps no copy of it.

Protocol compatibility is behavioral. Do not add logos, image assets, or text
that claims this project is someone else's cloud.

## Where things live

| Path | Owns |
| --- | --- |
| `internal/resource` | The one resource model: kinds, IDs, states, operations, errors, requests. Standard library only. |
| `internal/cloud` | The kernel. Normalization, idempotency keys, tenancy checks. One backend call per method. |
| `internal/backend` | The client contract (`Compute`, `Storage`, `Network`) in model types. |
| `internal/backend/fake` | In-memory backends that honor the contract. |
| `internal/backend/backendtest` | The contract as tests. Every backend implementation runs it. |
| `internal/backend/grpcclient` | The contract over gRPC. The only package that sees protobuf. |
| `internal/sigv4` | Signature verification, plus `Sign` for tests. |
| `internal/surface/console` | JSON codec. The body is the model. |
| `internal/surface/ec2query` | EC2 Query codec. |
| `internal/surface/s3rest` | Path-style object codec. |
| `internal/surface/interop` | Tests that drive more than one surface against one world. |
| `internal/server` | One listener per surface, request IDs, shutdown. |
| `third_party/vws-proto` | Vendored `github.com/popododo0720/vws-proto` (see the vws-proto pull request for the current commit; today `feat/iam-mfa-tags` c59a88d, which also carries `feat/iam-policy-tags` 8fa2ce8; re-pin after those pull requests merge). Imported through a `replace` directive. |

## Rules

Each rule names what enforces it. A rule with nothing behind it will be
copied around and then broken. If you add a rule, add its check in the same
change.

| Rule | Enforced by |
| --- | --- |
| Surfaces call `internal/cloud`, never `internal/backend`. | depguard `surfaces-use-the-kernel` |
| `internal/resource` imports only the standard library. | depguard `model-is-a-leaf` |
| The kernel never sees HTTP, signatures, or a surface. | depguard `kernel-knows-no-wire` |
| Protobuf and gRPC types stay inside `internal/backend/grpcclient`. | depguard `grpc-stays-in-grpcclient` |
| Untrusted strings become IDs only through `resource.Parse` or JSON decoding. | The compiler: ID types are structs with unexported fields |
| Surfaces and the kernel do not mint IDs or operation IDs. | `internal/hygiene` rejects `resource.Mint` and `resource.NewOperationID` outside `internal/backend` |
| Every switch over a model enum handles every value. | `exhaustive` |
| No package-level mutable state. The process is stateless. | `gochecknoglobals` |
| A long-running mutation takes a client token and returns `resource.Accepted`. It does not wait for the work to finish. | Kernel signatures; `cloud.mutate` is the only mutation path |
| A mutation publishes the resource, the operation, and the idempotency record together. A rejected call leaves the previous state, and a repeated minted id is an internal error. | `backendtest` partial stop; `TestRepeatedEntropyDoesNotOverwrite` |
| `RunInstances` requires a subnet the caller owns. | `backendtest` creates the subnet, then launches into it |
| An unknown page token is an invalid argument. A state filter does not turn an existing id into not-found. | `backendtest` |
| An object list with a delimiter returns common prefixes instead of the keys under them. The continuation token is a position in that rollup, so deleting the named key still resumes. `start-after` drops raw keys before the rollup, so a cursor inside a group keeps the group when a later key remains. | `TestObjectListGroupsByDelimiter`, `TestObjectListContinues`; `backendtest` |
| The idempotency key is the account, the action, and the client token. The fingerprint is `idempotencyVersion` plus the normalized JSON, including empty tag values. A derivation change mismatches a retry instead of minting a second resource. | Golden test and `TestEmptyTagChangesFingerprint` in `internal/cloud` |
| A backend result that names another account is rejected, including a polled operation and an object listing. The operation id returned must be the id that was requested. A caller with no account never reaches a backend. | `guardAccepted`, `guardOwner`, `guardOperation`, and `requireCaller` in `internal/cloud`, covered by `TestForeignAccountIsInternal`, `TestForeignOperationIsInternal`, `TestForeignObjectListingIsInternal`, and `TestZeroAccountIsUnauthenticated` |
| Each listener bounds header, body, write, and idle time. The process stops on interrupt and SIGTERM. A gRPC call without a deadline gets one. | `TestListenerBounds`, `TestStopOnSIGTERM`, `TestCallGetsADeadline` |
| Fakes and the gRPC client behave the same. Operation failure fields survive the gRPC mapping. An object at `MaxObjectBytes` fits in one gRPC message. A larger body is `PayloadTooLarge`, which is not the retryable quota code. | `backendtest.Run` on both; `TestObjectCapMatchesStorageProto`; `TestOperationFailureRoundTrip`; `TestBareResourceExhaustedStaysRetryable` |
| `-ops-addr` serves `/healthz`, `/readyz`, and `/metrics` on its own listener. `/readyz` is 503 once shutdown starts. Every metric series starts with `vws_`. | `TestOpsEndpoints`, `TestMetricsCountRequestsWithTheVWSPrefix`, `TestFakeProcessSmoke` |
| Credentials come from `VWS_CONSOLE_TOKEN`, `VWS_ACCESS_KEY`, `VWS_SECRET_KEY` or their `_FILE` paths; the `-console-token`, `-access-key`, `-secret` flags are deprecated (they show in the process arguments), win when given, and log a warning naming the flag, never the value. `X` and `X_FILE` together, or an empty or unreadable file, is an error. `-backend=grpc` refuses to start while any credential is at its public development default. | `TestGRPCRefusesDefaultCredentials`, `TestGRPCAcceptsCredentialsFromEnvAndFile`, `TestCredentialFlagWinsAndWarnsWithoutTheValue`, `TestCredentialFilePrecedesEnvOnlyWhenAloneElseError`, `TestCredentialFileErrors` |
| Every IAM and STS Query action except `sts:GetCallerIdentity` (which, as in AWS, needs only a valid signature) is authorized as `iam:<Action>` or `sts:<Action>` on the entity's real ARN (`*` for lists) before it runs. Tagging a policy also needs `iam:ListPolicyTags`, and tagging a virtual MFA device also needs `iam:ListMFADeviceTags`, as in AWS. Unknown parameters, including `PermissionsBoundary` and `Tags` on an action that does not take them, are rejected. A key or session deleted or expired stops authenticating at once. `AssumeRole` needs both the caller's `sts:AssumeRole` permission and the role's trust policy. Allow statements with a `Condition` never apply in the fake; Deny statements with one always do. | `TestIAMResponseAndErrorShapes`, `TestLimitedUserAndSTS`, `TestAssumeRole`, `TestAccessKeysAuthenticate`, `TestGetCallerIdentitySkipsAuthorizeButNotAuthentication`, e2e `identity()` |
| Every console route is authenticated (bearer root token or `vws_session` cookie) and authorized as an IAM action by `routeAction`; a route without an entry is denied, and `TestEveryRouteIsAuthorized` fails. A cookie session must send `X-CSRF-Token` (derived from the session token) on every non-GET/HEAD request. Sign-in failures are one uniform `401`; passwords are stored only as argon2id hashes and never logged or echoed. | `TestSessionIsAuthorizedPerRequest`, `TestLoginFailuresAreGeneric`, `TestLoginSetsHardenedCookies`, `TestEveryRouteIsAuthorized`, `TestLoginLockout`, e2e `console_login()` |
| With `-iam=grpc`, only `internal/backend/grpcclient/iamclient` speaks vws.iam.v1. The principal vws-iam names in `Authenticate` (unique id, resource, session name, MFA) travels on `resource.Caller.Ref` to `Authorize` unchanged; anything but `DECISION_ALLOW` denies; STS `AssumeRole` names the caller only in the request's `authentication` oneof (its SigV4 request or console session token), never in gRPC metadata or the deprecated `caller` field. Console sessions from vws-iam keep the same uniform `401` as the fake and fail closed on any other error. `Caller.Ref.Proof` is a credential and is never logged, and no access-key secret is ever sent to vws-iam. | `TestVerifierToAuthorizeKeepsThePrincipal`, `TestAuthorizeMapsPrincipalResourcesContextAndDecision`, `TestAssumeRoleSendsTheCallersAuthentication`, `TestAuthenticateMapsEveryFieldAndThePrincipal`, `TestSessionsContract`, `TestLoginErrorsMatchTheFake`, `TestSecretsNeverLeaveConsoleAPI`, `TestSessionCallerKeepsThePrincipalRef` |
| Every `resource.Action` has a console route. | `TestEveryActionHasARoute` |
| A query parameter or object subresource the codec does not apply is rejected. A bucket GET is ListObjects (no `list-type` or `list-type=1`, paged by `marker`) or ListObjectsV2 (`list-type=2`, paged by `continuation-token`); mixing their paging keys is `InvalidArgument` and any other list query key is `NotImplemented`. `RunInstances` requires `ClientToken`. The other EC2 query mutations accept a missing token. `CreateSubnet` derives one from the normalized request so a retry is the same subnet. The rest call `fillToken` before `mutate`. The console object read returns the bytes. | `TestUnsupportedFilterIsRejected`, `TestUnreadQueryFieldsAreRejected`, `TestClientTokenIsRequired`, `TestStopOmitsClientToken`, `TestStopRunningInstanceWithoutClientToken`, `TestCreateSubnetOmitsClientToken`, `TestIndexPastTheCapIsRejected`, `TestSubresourceDoesNotOverwrite`, `TestListObjectsV2`, `TestListObjectsV1`, `TestListBucketsContinues`, `TestS3ObjectRoundTrip` |
| The policy and virtual MFA device tag actions store tags with the resource, not in envelope labels. A tag member without `Value` is `ValidationError`; an invalid tag is `InvalidInput`; a missing resource is `NoSuchEntity`, and a virtual MFA device is looked up by its `SerialNumber`; the 51st tag is `LimitExceeded`; the list actions sort by key and page; a parameter the action does not take, such as `PathPrefix`, is rejected. | `TestPolicyTagActions`, `TestPolicyTagErrors`, `TestMFADeviceTagActions`, `TestMFADeviceTagErrors`, `TestMFADeviceTagNeedsListPermission`, `TestListMFADeviceTagsParameterErrors` |
| An operation name is `op-` plus 16 to 40 lowercase hex digits, or a lowercase UUID. Storage and compute mint 20 digits. A 32-digit value is the UUID form on the wire. A 500 logs the cause and leaves it off the wire body. | `TestOperationLocalServiceNames`, `TestCreateVolumeRetryKeepsTheVolumeID`, `TestInternalErrorIsLogged` |
| An object update mask is `spec` and `labels`, or empty. A spec-only mask is rejected, including on overwrite. | `TestObjectMaskMatches`; `backendtest` object overwrite |
| A PutObject request id includes the payload hash. The same body retries the original write. A different body is a new request, so an overwrite is not an idempotency conflict. | `TestPutRequestIDTracksContents`; `backendtest` object overwrite |
| `If-None-Match: *` on PutObject is write-once: an existing key, even with the same bytes, is `AlreadyExists` of `KindObject`, which S3 answers 412 `PreconditionFailed`. Over gRPC it is a `GetObject` check, then `CreateObject`. Any other `If-None-Match` value is `NotImplemented`. | `backendtest` conditional put; `TestPutIfNoneMatchIsWriteOnce` |
| PutObject polls the storage operation until it is done, then reads the object. A not-yet-visible object is not a 404. | `TestPutObjectWaitsForTheOperation` |
| `DescribeKeyPairs`, `DeleteKeyPair`, `DescribeSecurityGroups`, `DeleteSecurityGroup`, `DeleteSubnet`, `DescribeAddresses`, `AllocateAddress`, `ReleaseAddress`, `AssociateAddress`, `DisassociateAddress`, `DescribeSnapshots`, `CreateSnapshot`, and `DeleteSnapshot` are served on the console and the query surface. A missing selector is a parameter error. Deleting a subnet that still has an instance is `DependencyViolation`. A group name that matches more than one group is invalid. Polling a delete reports that action. A subnet created again after it is deleted is a new id. An id delete retried after it succeeds returns the same operation. Query describe returns the group's rules. An association is `spec.association` on the address (UpdateAddress) and its id is `eipassoc-` with the allocation digits. | `TestCatalogActionsAreImplemented`, `TestAssociateAndDisassociateAddress`, `TestAssociationIDNamesItsAddress`, `TestConsoleAndQueryShareAnAddress`, `TestCreateSubnetOmitsClientToken`, `TestDescribeSecurityGroupReturnsRules`, `TestDeleteUnderVpcKeepsItsAction`, `exerciseEC2` |
| `AllocateAddress` ensures the account default VPC (`172.31.0.0/16`) when the project has none. The address proto has no VPC field. An address binds to the oldest VPC: create time, then name. | `TestAllocateAddressEnsuresDefaultVPC`, `TestEnsureVPCIgnoresListOrder` |
| Describe calls accept the query names boto3 sends. `DescribeSnapshots` keeps `Owner` and `OwnerId` (`OwnerIds=['self']`) and `RestorableBy`. `DescribeImages` keeps `Owner` and `ExecutableBy`. `dryRun` is rejected. `maxResults` and `nextToken` page the same way as `MaxResults` and `NextToken`. An owner other than `self` or the caller is an empty page. A filter this codec does not apply is rejected. | `TestDescribeStandardParameters` |
| `CreateVolume` with `SnapshotId` restores through `VolumeSpec.snapshot`. A left-out size is the snapshot size, and a smaller one is invalid. A restored volume is a `DescribeVolumes` row with its `snapshotId`; only an image-sourced volume is a boot volume. | `backendtest` restore; `TestCreateVolumeFromSnapshot` |
| A boot volume is not a `DescribeVolumes` row. `AuthorizeSecurityGroupIngress` writes the whole rule list. Polling `StartInstances` reports that action, from the `vws-action` label. | `exerciseEC2` |
| `RunInstances` creates the boot volume from `VolumeSpec.image`. `InstanceSpec` does not reference an image. | `TestBootVolumeSourcesTheImage` |
| `RunInstances` launches an AMI only when `KnownImages` for the caller names that id in this region. A catalog AMI is in-region when compute has no Image for it. Any other id is the same `NotFound` of `KindImage`, message `The image id '[ami-xxxxxxxx]' does not exist`, which EC2 answers as 400 `InvalidAMIID.NotFound`. The check is before `CreateVolume` and `CreateInstance`. | `TestRunInstancesRequiresImageInCallerRegion`, `TestInvalidAMIIDNotFoundShape` |
| A compute reconciliation ERROR is a terminated instance (code 48) with state reason `Server.InternalError`. A storage reconciliation ERROR is volume state `error`, including when the volume names an instance. One such record does not fail `DescribeInstances` or `DescribeVolumes`. `TerminateInstances` on that instance is accepted, calls delete, and a repeat returns the same terminated states. An unspecified or unknown reconciliation state is listed the same way, so one record cannot fail a listing (#191, #197). | `TestErrorRecordDoesNotFailDescribe`, `TestTerminateErrorInstanceIsIdempotent`, `TestStateReasonOnDescribeInstancesXML`, `TestUnreadableReconcileIsAFailedRecord`, `TestOrphanBootVolumeFromRefusedLaunchIsListed` |
| A backend record whose name is not a valid resource id is skipped and logged in a listing, so it does not fail `DescribeInstances` or `DescribeVolumes`. An explicit id read still returns the internal error. | `TestInvalidResourceNameIsSkippedInList` |
| `CreateKeyPair`'s private key is not the hash published as the key id or the request id. | `TestKeySeedIsNotThePublishedID` |
| Volume and snapshot create and delete operations are read from the storage service. A subnet in `DELETING` stays a subnet state. | `TestContractOverGRPC` uses a separate storage listener; `TestSubnetDeletingRoundTrip` |
| A missing resource read by name is `NotFound` of the kind its name's collection names, so EC2 answers `InvalidVolume.NotFound`, `InvalidSnapshot.NotFound`, `InvalidInstanceID.NotFound`, and the like, not `InvalidParameterValue`. | `TestMissingResourceKeepsItsKind`; e2e `not_found` |
| `DisassociateAddress` on an unknown address or one with no association is `resource.AssociationNotFound`, which EC2 answers 400 `InvalidAssociationID.NotFound`. Over gRPC it is a `GetAddress` that finds neither `spec.association` nor `status.instance`. | `exerciseEC2`; `TestAssociateAndDisassociateAddress`; e2e `not_found` |
| An unknown ingress protocol is invalid. It is not stored as tcp. | `TestIngressProtocolIsCanonical` |
| The signature is checked after the access key is known and before the body is trusted. A missing payload hash is the hash of the body. `UNSIGNED-PAYLOAD` is rejected. A query longer than 128 parameters is rejected before it is sorted. | `TestQueryWithoutPayloadHeader`, `TestUnsignedPayloadAndUnreadBody`, `TestTooManyQueryParams` |
| A resource created on one surface is the same resource, with the same id and state names, on the others. | `internal/surface/interop` |
| Console JSON field names are camelCase. | `tagliatelle` |
| The resource API is the vendored module. This repo does not generate it and does not keep a local proto tree. | `internal/hygiene` checks the `replace` directive and rejects `proto/` |
| Google Go style and formatting. | golangci-lint in CI job `lint` |
| Tests pass under the race detector. | CI job `test` |
| `//nolint` names one linter and gives a reason. | `nolintlint` |
| No swallowed errors. A blank error, an unchecked type assertion, `if err != nil { return nil }`, and an unwrapped foreign error fail lint. Tests are exempt from errcheck and wrapcheck. | `errcheck` (check-blank, check-type-assertions), `nilerr`, `nilnil`, `wrapcheck`, `errorlint`, `errname`, `contextcheck`, `sloglint` |
| Every `resource.Code` has a status and wire code on each surface. | `TestEveryCodeHasAnEC2Error`, `TestEC2ErrorByKind`, `TestEveryCodeHasAnS3Error`, `TestEveryCodeHasAnIAMError`, `TestEveryCodeHasAConsoleStatus` |
| Console JSON `NotFound` is HTTP 404. EC2 Query `*.NotFound` is HTTP 400. S3 `NoSuchBucket` and `NoSuchKey` are HTTP 404. IAM `NoSuchEntity` is HTTP 404. | `TestMissingResourceStatusIsPerSurface` |
| A handler panic is a bare 500. The panic value goes to the log only. A failed response write is logged as a warning. | `TestPanicIsABare500`, `TestWriteFailureIsLogged` |
| A repeated query parameter, `Authorization` header, or `Authorization` field is an invalid argument. Bucket names, key length, and body size are checked before the backend. | `TestMalformedQueryIsRejected`, `TestAmbiguousAuthorizationIsRejected`, `TestMalformedNamesAndBodies` |
| No image assets. | CI job `hygiene`; `internal/hygiene` |
| No branding lines and no vendor API host names. | `internal/hygiene` |
| No deployment manifests (Dockerfile, compose, Helm, k8s). CI lints and tests. The only release step is `.github/workflows/publish.yml`: on a push to main, ko builds the image and pushes `ghcr.io/<owner>/vws/console-api:sha-<7-char commit>` with `org.opencontainers.image.revision` (popododo0720/vws-deploy#280). | CI job `hygiene`; `internal/hygiene`; `publish.yml` |
| Never push to `main`. | `.githooks/pre-push` after `git config core.hooksPath .githooks` |
| Work on a branch. Each commit is one logical change and passes tests by itself. | Review. Before review: `git rebase -x 'go test ./...' origin/main` |
| Structural changes use pstack: architect, then interrogate, then correct. | Review: the pull request names the sketch and the interrogate verdict |
| The repo is English only (see "English only"). Hangul is allowed only in files `.github/english-allowlist` lists with a reason (today: Unicode tag test data). | `scripts/check-english.sh` (CI job `english`) |

## e2e

`e2e/e2e.py` drives the EC2 Query and S3 entry points with boto3.
`VWS_E2E_BACKEND` is `fake` or `grpc`. `VWS_E2E_CAPS` lists what the backend
can do (`vm`, `eip`). A step that needs a missing capability prints
`skipped(reason)` and does not count as a pass. The run ends with a banner
that lists every skip and `status=PASS|FAIL|INCOMPLETE`. `VWS_E2E_STRICT=1`
makes a skip exit 3. CI sets it, so the fake run cannot lose a step silently.

```sh
pip install -r e2e/requirements.txt
e2e/run.sh                          # fake backend, started by the script
VWS_E2E_BACKEND=grpc python3 e2e/e2e.py   # services already running
e2e/local.sh                        # grpc stack kept up for manual runs (needs VWS_E2E_BIN, VWS_E2E_IMAGES)
```

## pstack

Use these three skills, in this order, when the change adds a package, a type
other packages use, a surface, or a backend method.

1. **architect**. Sketch the caller's usage first, then the types and
   signatures. Do not start from a wire format and grow a second vocabulary.
2. **interrogate**. Put the sketch or the diff in front of more than one
   reviewer before treating it as done. Act on findings that break
   correctness, tenancy, or the single resource model.
3. **correct**. When a review catches a mistake a later agent would copy,
   make that mistake fail a compile, a lint, or a test. Update the rule
   table in the same change. Do not leave the rule as prose alone.

## Dev style

Work in poteto-mode style.

- Write short declarative sentences in code comments, commits, and PRs.
- Keep code simple and the diff minimal. Delete before adding.
- Prove a change against real artifacts. Run it and paste the output.
- One issue is one branch and one PR. Commits are atomic.
- Verify T0 only: unit tests, fakes, and envtest. T1 and T2 are run by the verification bot.
- Never force-push. Never merge your own PR. The reviewer merges.

## Agents

Do not use Cursor cloud agents on this repository. Use Grok dev bots only.

## Workflow

1. Branch from `main`. Do not commit on `main`.
2. Follow pstack for a structural change.
3. Keep commits atomic. One commit does not mix a refactor with a behavior change.
4. Before pushing, run `golangci-lint run` and `go test -race ./...`.
5. Push the branch and open a pull request.

## Adding a long-running action

1. Add the `Action` constant in `internal/resource`, plus its request type
   (`Action` and `Normalize`) and any lifecycle row. `exhaustive` flags a
   switch that misses it. `Actions()` is derived from the constants.
2. Add the method on the backend interface. The fake and the gRPC client stop
   compiling until they implement it.
3. Add the case to `backendtest`.
4. Add a one-line kernel method that calls `mutate`.
5. Add the console route in `handler.mutation`. `TestEveryActionHasARoute` fails until the route is real.
6. Add the query action in `ec2query` when the query protocol has that action.
7. Add an interop test when a second surface can perform the same mutation.

## Commands

```sh
go test -race ./...
golangci-lint run
git config core.hooksPath .githooks
go run ./cmd/vws-console-api -backend=fake
```

## English only

Write everything in this repo in English: README, code comments, docs, AGENTS.md, QUALITY.md, PR and issue templates, commit messages, PR and issue bodies, review comments and `Verified-by` sections. The `english` job in CI runs `scripts/check-english.sh`: `files` fails on a tracked file with Hangul unless `.github/english-allowlist` lists it as `<glob> <reason>` (only test data and user-facing UI strings belong there), and `text` and `commits` reject Hangul in the PR body and the PR's commit messages with no exception.

## Insider-risk guardrails

Bots are insider risks too. The rules below have no exceptions.

1. **Independent verification**: an important result (merge, security, data) is never verified by the bot/model that wrote it. Another bot (or a person) verifies it. (Process rule; CI cannot enforce it.)
2. **Records**: every change leaves a trail of issue → PR (`Part of #N`) → commits. Work logs go in the PR body or issue comments in a form people can read. No force-push or history rewriting (except with the user's approval).
3. **Failure tests**: a new feature is not tested on the happy path only. Include at least one case each for power loss/restart, idempotent re-run and malicious or boundary input, or state in the PR why that is not possible.
4. **Least privilege**: no direct pushes to main. Every change is a single PR from its own branch cut from main. No stacked PRs. No local merges. Tokens are scoped to the repo. RBAC covers only the resources the service code actually calls, as a Role (namespace scope) where possible.
5. **Separated audit**: author bot ≠ verifier bot ≠ merge decision. An author bot never merges its own PR. Merge only when base==main and every CI check on the head commit is success.
6. **Isolation and emergency stop**: a bot/agent is stopped immediately at the user's request or by the orchestrator stopping that bot's session and revoking its token (`gh auth`/PAT revoke). Risky work happens only in a sandbox (the box or a throwaway cluster). No access to production clusters.
7. **Incident disclosure**: rule violations and incidents are never hidden; record them in an issue as `Cause / Impact / Action / Prevention` (label `incident`).
