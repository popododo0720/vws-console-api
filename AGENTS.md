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
| Fakes and the gRPC client behave the same. Operation failure fields survive the gRPC mapping. An object at `MaxObjectBytes` fits in one gRPC message. A larger body is `PayloadTooLarge`, which is not the retryable quota code. | `backendtest.Run` on both; `TestOperationFailureRoundTrip`; `TestBareResourceExhaustedStaysRetryable` |
| Every `resource.Action` has a console route. | `TestEveryActionHasARoute` |
| A query parameter or object subresource the codec does not apply is rejected. ListObjectsV2 requires `list-type=2`; any other list query key is `NotImplemented`. `RunInstances` requires `ClientToken`. The other EC2 query mutations accept a missing token. `CreateSubnet` derives one from the normalized request so a retry is the same subnet. The rest call `fillToken` before `mutate`. The console object read returns the bytes. | `TestUnsupportedFilterIsRejected`, `TestUnreadQueryFieldsAreRejected`, `TestClientTokenIsRequired`, `TestStopOmitsClientToken`, `TestCreateSubnetOmitsClientToken`, `TestStopOmitsClientToken`, `TestIndexPastTheCapIsRejected`, `TestSubresourceDoesNotOverwrite`, `TestListObjectsV2`, `TestListBucketsContinues`, `TestS3ObjectRoundTrip` |
| An operation name is `op-` plus 16 to 40 lowercase hex digits, or a lowercase UUID. Storage and compute mint 20 digits. A 32-digit value is the UUID form on the wire. A 500 logs the cause and leaves it off the wire body. | `TestOperationLocalServiceNames`, `TestCreateVolumeRetryKeepsTheVolumeID`, `TestInternalErrorIsLogged` |
| An object update mask is `spec` and `labels`, or empty. A spec-only mask is rejected, including on overwrite. | `TestObjectMaskMatches`; `backendtest` object overwrite |
| A PutObject request id includes the payload hash. The same body retries the original write. A different body is a new request, so an overwrite is not an idempotency conflict. | `TestPutRequestIDTracksContents`; `backendtest` object overwrite |
| PutObject polls the storage operation until it is done, then reads the object. A not-yet-visible object is not a 404. | `TestPutObjectWaitsForTheOperation` |
| `DescribeKeyPairs`, `DeleteKeyPair`, `DescribeSecurityGroups`, `DeleteSecurityGroup`, `DeleteSubnet`, `DescribeAddresses`, `AllocateAddress`, `ReleaseAddress`, `DescribeSnapshots`, `CreateSnapshot`, and `DeleteSnapshot` are served on the console and the query surface. A missing selector is a parameter error. Deleting a subnet that still has an instance is `DependencyViolation`. A group name that matches more than one group is invalid. Polling a delete reports that action. A subnet created again after it is deleted is a new id. An id delete retried after it succeeds returns the same operation. Query describe returns the group's rules. | `TestCatalogActionsAreImplemented`, `TestConsoleAndQueryShareAnAddress`, `TestCreateSubnetOmitsClientToken`, `TestDescribeSecurityGroupReturnsRules`, `TestDeleteUnderVpcKeepsItsAction`, `exerciseEC2` |
| `AllocateAddress` ensures the account default VPC (`172.31.0.0/16`) when the project has none. The address proto has no VPC field. | `TestAllocateAddressEnsuresDefaultVPC` |
| Describe calls accept the query names boto3 sends. `DescribeSnapshots` keeps `Owner` and `OwnerId` (`OwnerIds=['self']`) and `RestorableBy`. `DescribeImages` keeps `Owner` and `ExecutableBy`. `dryRun` is rejected. `maxResults` and `nextToken` page the same way as `MaxResults` and `NextToken`. An owner other than `self` or the caller is an empty page. A filter this codec does not apply is rejected. | `TestDescribeStandardParameters` |
| A boot volume is not a `DescribeVolumes` row. `AuthorizeSecurityGroupIngress` writes the whole rule list. Polling `StartInstances` reports that action, from the `vws-action` label. | `exerciseEC2` |
| `RunInstances` creates the boot volume from `VolumeSpec.image`. `InstanceSpec` does not reference an image. | `TestBootVolumeSourcesTheImage` |
| `CreateKeyPair`'s private key is not the hash published as the key id or the request id. | `TestKeySeedIsNotThePublishedID` |
| Volume and snapshot create and delete operations are read from the storage service. A subnet in `DELETING` stays a subnet state. | `TestContractOverGRPC` uses a separate storage listener; `TestSubnetDeletingRoundTrip` |
| An unknown ingress protocol is invalid. It is not stored as tcp. | `TestIngressProtocolIsCanonical` |
| The signature is checked after the access key is known and before the body is trusted. A missing payload hash is the hash of the body. `UNSIGNED-PAYLOAD` is rejected. A query longer than 128 parameters is rejected before it is sorted. | `TestQueryWithoutPayloadHeader`, `TestUnsignedPayloadAndUnreadBody`, `TestTooManyQueryParams` |
| A resource created on one surface is the same resource, with the same id and state names, on the others. | `internal/surface/interop` |
| Console JSON field names are camelCase. | `tagliatelle` |
| The resource API is the vendored module. This repo does not generate it and does not keep a local proto tree. | `internal/hygiene` checks the `replace` directive and rejects `proto/` |
| Google Go style and formatting. | golangci-lint in CI job `lint` |
| Tests pass under the race detector. | CI job `test` |
| `//nolint` names one linter and gives a reason. | `nolintlint` |
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
`skipped(reason)` and does not count as a pass.

```sh
pip install -r e2e/requirements.txt
e2e/run.sh                          # fake backend, started by the script
VWS_E2E_BACKEND=grpc python3 e2e/e2e.py   # services already running
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
