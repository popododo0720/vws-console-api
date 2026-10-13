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
| `third_party/vws-proto` | Vendored `github.com/popododo0720/vws-proto` (main `a1c6084`). Imported through a `replace` directive. |

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
| `-backend=grpc` refuses to start unless `-console-token`, `-access-key`, and `-secret` are given on the command line. The defaults are public development credentials. | `TestGRPCRefusesDefaultCredentials` |
| Every `resource.Action` has a console route. | `TestEveryActionHasARoute` |
| A query parameter or object subresource the codec does not apply is rejected. A bucket GET is ListObjects (no `list-type` or `list-type=1`, paged by `marker`) or ListObjectsV2 (`list-type=2`, paged by `continuation-token`); mixing their paging keys is `InvalidArgument` and any other list query key is `NotImplemented`. `RunInstances` requires `ClientToken`. The other EC2 query mutations accept a missing token. `CreateSubnet` derives one from the normalized request so a retry is the same subnet. The rest call `fillToken` before `mutate`. The console object read returns the bytes. | `TestUnsupportedFilterIsRejected`, `TestUnreadQueryFieldsAreRejected`, `TestClientTokenIsRequired`, `TestStopOmitsClientToken`, `TestStopRunningInstanceWithoutClientToken`, `TestCreateSubnetOmitsClientToken`, `TestIndexPastTheCapIsRejected`, `TestSubresourceDoesNotOverwrite`, `TestListObjectsV2`, `TestListObjectsV1`, `TestListBucketsContinues`, `TestS3ObjectRoundTrip` |
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
| `CreateKeyPair`'s private key is not the hash published as the key id or the request id. | `TestKeySeedIsNotThePublishedID` |
| Volume and snapshot create and delete operations are read from the storage service. A subnet in `DELETING` stays a subnet state. | `TestContractOverGRPC` uses a separate storage listener; `TestSubnetDeletingRoundTrip` |
| A missing resource read by name is `NotFound` of the kind its name's collection names, so EC2 answers `InvalidVolume.NotFound`, `InvalidSnapshot.NotFound`, `InvalidInstanceID.NotFound`, and the like, not `InvalidParameterValue`. | `TestMissingResourceKeepsItsKind`; e2e `not_found` |
| An unknown ingress protocol is invalid. It is not stored as tcp. | `TestIngressProtocolIsCanonical` |
| The signature is checked after the access key is known and before the body is trusted. A missing payload hash is the hash of the body. `UNSIGNED-PAYLOAD` is rejected. A query longer than 128 parameters is rejected before it is sorted. | `TestQueryWithoutPayloadHeader`, `TestUnsignedPayloadAndUnreadBody`, `TestTooManyQueryParams` |
| A resource created on one surface is the same resource, with the same id and state names, on the others. | `internal/surface/interop` |
| Console JSON field names are camelCase. | `tagliatelle` |
| The resource API is the vendored module. This repo does not generate it and does not keep a local proto tree. | `internal/hygiene` checks the `replace` directive and rejects `proto/` |
| Google Go style and formatting. | golangci-lint in CI job `lint` |
| Tests pass under the race detector. | CI job `test` |
| `//nolint` names one linter and gives a reason. | `nolintlint` |
| No swallowed errors. A blank error, an unchecked type assertion, `if err != nil { return nil }`, and an unwrapped foreign error fail lint. Tests are exempt from errcheck and wrapcheck. | `errcheck` (check-blank, check-type-assertions), `nilerr`, `nilnil`, `wrapcheck`, `errorlint`, `errname`, `contextcheck`, `sloglint` |
| Every `resource.Code` has a status and wire code on each surface. | `TestEveryCodeHasAnEC2Error`, `TestEC2ErrorByKind`, `TestEveryCodeHasAnS3Error`, `TestEveryCodeHasAConsoleStatus` |
| A handler panic is a bare 500. The panic value goes to the log only. A failed response write is logged as a warning. | `TestPanicIsABare500`, `TestWriteFailureIsLogged` |
| A repeated query parameter, `Authorization` header, or `Authorization` field is an invalid argument. Bucket names, key length, and body size are checked before the backend. | `TestMalformedQueryIsRejected`, `TestAmbiguousAuthorizationIsRejected`, `TestMalformedNamesAndBodies` |
| No image assets. | CI job `hygiene`; `internal/hygiene` |
| No branding lines and no vendor API host names. | `internal/hygiene` |
| No deployment setup. CI only lints and tests. | CI job `hygiene`; `internal/hygiene` |
| Never push to `main`. | `.githooks/pre-push` after `git config core.hooksPath .githooks` |
| Work on a branch. Each commit is one logical change and passes tests by itself. | Review. Before review: `git rebase -x 'go test ./...' origin/main` |
| Structural changes use pstack: architect, then interrogate, then correct. | Review: the pull request names the sketch and the interrogate verdict |

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

## Insider-risk guardrails

봇도 내부자 위험이다. 아래는 예외 없는 규칙이다.

1. **검증 독립**: 중요 결과(머지, 보안, 데이터)는 작성한 봇/모델이 스스로 검증하지 않는다. 검증은 작성 봇이 아닌 다른 봇(또는 사람)이 한다. (프로세스 규칙, CI로 강제 불가)
2. **기록**: 모든 변경은 이슈 → PR(`Closes #N`) → 커밋으로 남긴다. 작업 로그는 PR 본문/이슈 코멘트에 사람이 읽을 수 있게 쓴다. force-push·히스토리 재작성 금지(사용자 승인 시 예외).
3. **실패 테스트**: 새 기능은 정상 경로만 테스트하지 않는다. 전원 차단/재시작, 멱등 재실행, 악성·경계 입력 케이스를 최소 1개씩 포함하거나 불가 사유를 PR에 적는다.
4. **최소 권한**: main 직접 푸시 금지. 모든 변경은 main에서 딴 독립 브랜치의 단일 PR. 스택 PR 금지. 로컬 머지 금지. 토큰은 해당 레포 범위만. RBAC은 서비스 코드가 실제 호출하는 리소스만, 가능하면 Role(네임스페이스 범위).
5. **감사 분리**: 작성 봇 ≠ 검증 봇 ≠ 머지 판단. 작성 봇은 자기 PR을 머지하지 않는다. 머지는 base==main 이고 head 커밋 CI가 전부 success일 때만.
6. **격리·비상정지**: 봇/에이전트 즉시 중단은 사용자 요청 또는 오케스트레이터가 해당 봇 세션 중단 + 토큰 폐기(`gh auth`/PAT revoke). 위험 작업은 샌드박스(박스/임시 클러스터)에서만. 운영 클러스터 접근 금지.
7. **사고 공개**: 규칙 위반·사고는 숨기지 않고 이슈에 `원인 / 영향 / 조치 / 재발방지`로 기록한다 (라벨 `incident`).
