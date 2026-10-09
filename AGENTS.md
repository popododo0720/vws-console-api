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
| `proto/` | The internal service contracts. Generated Go is committed. |

## Rules

Each rule names what enforces it. A rule with nothing behind it will be
copied around and then broken. If you add a rule, add its check in the same
change.

| Rule | Enforced by |
| --- | --- |
| Surfaces call `internal/cloud`, never `internal/backend`. | depguard `surfaces-use-the-kernel` |
| `internal/resource` imports only the standard library. | depguard `model-is-a-leaf` |
| The kernel never sees HTTP, signatures, or a surface. | depguard `kernel-knows-no-wire` |
| Protobuf and gRPC types stay inside `internal/backend/grpcclient`. | `grpcclient/internal` visibility; depguard `grpc-stays-in-grpcclient` |
| Untrusted strings become IDs only through `resource.Parse` or JSON decoding. | The compiler: ID types are structs with unexported fields |
| Surfaces and the kernel do not mint IDs or operation IDs. | `internal/hygiene` rejects `resource.Mint` and `resource.NewOperationID` outside `internal/backend` |
| Every switch over a model enum handles every value. | `exhaustive` |
| No package-level mutable state. The process is stateless. | `gochecknoglobals` |
| A long-running mutation takes a client token and returns `resource.Accepted`. It does not wait for the work to finish. | Kernel signatures; `cloud.mutate` is the only mutation path |
| A mutation publishes the resource, the operation, and the idempotency record together. A rejected call leaves the previous state, and a repeated minted id is an internal error. | `backendtest` partial stop; `TestRepeatedEntropyDoesNotOverwrite` |
| `RunInstances` requires a subnet the caller owns. | `backendtest` creates the subnet, then launches into it |
| An unknown page token is an invalid argument. A state filter does not turn an existing id into not-found. | `backendtest` |
| The idempotency key is the account, the action, and the client token. The fingerprint is `idempotencyVersion` plus the normalized JSON, including empty tag values. A derivation change mismatches a retry instead of minting a second resource. | Golden test and `TestEmptyTagChangesFingerprint` in `internal/cloud` |
| A backend result that names another account is rejected, including a polled operation. The operation id returned must be the id that was requested. | `guardAccepted`, `guardOwner`, and `guardOperation` in `internal/cloud`, covered by `TestForeignAccountIsInternal` and `TestForeignOperationIsInternal` |
| Fakes and the gRPC client behave the same. Operation failure fields survive the gRPC mapping. An object at `MaxObjectBytes` fits in one gRPC message. A larger body is `PayloadTooLarge`, which is not the retryable quota code. | `backendtest.Run` on both; `TestOperationFailureRoundTrip`; `TestBareResourceExhaustedStaysRetryable` |
| Every `resource.Action` has a console route. | `TestEveryActionHasARoute` |
| A resource created on one surface is the same resource, with the same id and state names, on the others. | `internal/surface/interop` |
| Console JSON field names are camelCase. | `tagliatelle` |
| Generated code matches `proto/`. | CI job `generated` |
| Google Go style and formatting. | golangci-lint in CI job `lint` |
| Tests pass under the race detector. | CI job `test` |
| `//nolint` names one linter and gives a reason. | `nolintlint` |
| No image assets. | CI job `hygiene`; `internal/hygiene` |
| No branding lines and no vendor API host names. | `internal/hygiene` |
| No deployment setup. CI only lints and tests. | CI job `hygiene`; `internal/hygiene` |
| Never push to `main`. | `.githooks/pre-push` after `git config core.hooksPath .githooks` |
| Work on a branch. Each commit is one logical change and passes tests by itself. | Review. Before review: `git rebase -x 'go test ./...' origin/main` |
| Structural changes use pstack: architect, then interrogate, then correct. | Review: the pull request names the sketch and the interrogate verdict |

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
buf generate
git config core.hooksPath .githooks
go run ./cmd/vws-console-api -backend=fake
```
