# AGENTS.md

The web-only backend of VWS, a private cloud with an AWS-shaped control
plane. One stateless process serves the console JSON API, an EC2 Query entry
point and an S3 REST entry point. Compute, storage and network state lives in
internal services reached over gRPC; this process keeps no copy. Protocol
compatibility is behavioral: no logos, image assets or text that claims this
project is someone else's cloud.

## Where things live

| Path | Owns |
| --- | --- |
| `internal/resource` | The one resource model: kinds, IDs, states, operations, errors, requests. Standard library only. |
| `internal/cloud` | The kernel: normalization, idempotency keys, tenancy checks. One backend call per method. |
| `internal/backend` | The client contract (`Compute`, `Storage`, `Network`) in model types. |
| `internal/backend/fake` | In-memory backends that honor the contract. |
| `internal/backend/backendtest` | The contract as tests. Every backend runs it. |
| `internal/backend/grpcclient` | The contract over gRPC. The only package that sees protobuf. |
| `internal/sigv4` | Signature verification, plus `Sign` for tests. |
| `internal/surface/*` | `console` (JSON), `ec2query`, `s3rest` codecs; `interop` drives several surfaces against one world. |
| `internal/server` | One listener per surface, request IDs, shutdown. |

## Rules

Each rule names what enforces it. A rule with nothing behind it gets copied
and then broken, so a new rule comes with its check in the same change. The
full statement of every rule and all of its checks are in `docs/rules.md`;
change both files together.

| Rule | Enforced by |
| --- | --- |
| Surfaces call `internal/cloud`, never `internal/backend`. | depguard `surfaces-use-the-kernel` |
| `internal/resource` imports only the standard library. | depguard `model-is-a-leaf` |
| The kernel never sees HTTP, signatures or a surface. | depguard `kernel-knows-no-wire` |
| Protobuf and gRPC types stay in `internal/backend/grpcclient`. | depguard `grpc-stays-in-grpcclient` |
| Untrusted strings become IDs only through `resource.Parse` or JSON decoding. | The compiler (unexported ID fields) |
| Only `internal/backend` mints IDs and operation IDs. | `internal/hygiene` |
| Every switch over a model enum handles every value. | `exhaustive` |
| No package-level mutable state. | `gochecknoglobals` |
| A long-running mutation takes a client token and returns `resource.Accepted` through `cloud.mutate`. | The compiler (kernel signatures) |
| A mutation publishes resource, operation and idempotency record together. | `TestRepeatedEntropyDoesNotOverwrite` |
| The idempotency key is account, action and client token. | `TestIdempotencyGolden` |
| A backend result naming another account is internal. | `TestForeignAccountIsInternal` |
| Listeners bound every timeout; SIGTERM stops; gRPC calls get a deadline. | `TestListenerBounds`, `TestCallGetsADeadline` |
| Fakes and the gRPC client behave the same. | `backendtest.Run` |
| Ops endpoints and `vws_` metrics. | `TestOpsEndpoints` |
| Credentials come from env or files; grpc refuses defaults; values never logged. | `TestGRPCRefusesDefaultCredentials` |
| IAM and STS actions validate UserName first, at each action's AWS limit (64 or 128), then authorize on the real ARN; a failed lookup authorizes nothing. | `TestUserNameValidationPrecedesAuthorization`, `TestUserNameLengthFollowsTheAWSLimitOfEachAction`, `TestEntityActionsFailClosedWhenTheLookupFails` |
| `GetCallerIdentity` answers the caller ARN in the `aws` partition. | `TestGetCallerIdentityReturnsAWSARNs` |
| Every console route is authenticated and authorized. | `TestEveryRouteIsAuthorized` |
| Only `iamclient` speaks vws.iam.v1; no secret reaches vws-iam. | `TestSecretsNeverLeaveConsoleAPI` |
| Named-entity `iam.Admin` methods take an `iam.AuthorizedPrincipal`, built only by `iam.Authorize`. | `TestOnlyTheAuthorizerBuildsAnAuthorizedPrincipal` |
| IAM tag, MFA, access key and policy actions follow AWS and act only on the authorized entity. | `TestAccessKeyCallsActOnTheAuthorizedARN`, `TestEntityPolicyCallsActOnTheAuthorizedARN`, `TestMFADeviceTagSerialValidationPrecedesAuthorization` |
| Access key secrets and policy documents are never logged or traced. | `TestAccessKeySecretIsNeverLoggedOrTraced` |
| Every `resource.Action` has a console route. | `TestEveryActionHasARoute` |
| An unapplied query parameter, filter or subresource is rejected. | `TestUnreadQueryFieldsAreRejected` |
| Operation names and 500s follow `docs/rules.md`. | `TestOperationLocalServiceNames`, `TestInternalErrorIsLogged` |
| S3 object writes: mask, request id, `If-None-Match`, waiting for the operation. | `TestPutIfNoneMatchIsWriteOnce`, `TestPutObjectWaitsForTheOperation` |
| S3 bucket creates answer as S3 outside us-east-1. | `backendtest.BucketCreate` |
| EC2 catalog actions are served on both surfaces. | `TestCatalogActionsAreImplemented` |
| EC2 describe calls take boto3's parameter names. | `TestDescribeStandardParameters` |
| EC2 instance, image, volume and address behavior. | `exerciseEC2`, `backendtest.AttachLifecycle` |
| A volume or block device is `attached` only when compute reports `ATTACHED` on `InstanceStatus.volumes`; no surface defaults to `attached` (#448). | `TestDescribeVolumesFollowsComputeAttachState`, `TestInstanceBlockDeviceStatus`, `backendtest.AttachLifecycle` |
| One bad backend record never fails a listing. | `TestErrorRecordDoesNotFailDescribe`, `TestInvalidResourceNameIsSkippedInList` |
| Key pair keys come from `crypto/rand`, are never stored, and names stay unique. | `TestCreatedKeyIsNotDerivedFromTheRequest`, `TestConcurrentCreatesOfOneNameMakeOneKeyPair` |
| A missing resource is `NotFound` of its own kind; an EC2, EBS or VPC resource and an S3 bucket carry the AWS message for that kind, naming the id where AWS does. | `TestMissingResourceKeepsItsKind`, `TestNotFoundMessagesMatchAWS`, `TestNoSuchBucketMessagesMatchAWS` |
| A malformed instance ID is `InvalidInstanceID.Malformed` on every EC2 action that takes one. | `TestMalformedInstanceIDIsInvalidInstanceIDMalformed` |
| A `DetachVolume` retry returns the first detach, within the label budget. Its four known limits wait on vws-proto#57, for the reasons in `docs/rules.md` (#317). | `backendtest.DetachReplay`, `backendtest.DetachWindow` |
| The detach recovery path matches `docs/formal/detach.tla` (pstack `create-formal-verification-skill` 0.15.30). | CI workflow `tla` (job `detach`) |
| Volume types map one to one; an unknown type is refused. | `TestVolumeTypeRefusesUnknown` |
| RunInstances creates the root volume with the root device mapping's type (gp2 when omitted), Ebs.Iops and Ebs.Throughput under the CreateVolume per-type rules on the 8 GiB root, with the gp3 defaults when omitted; any other device mapping is refused. | `TestRunInstancesRootVolumeTypeRoundTrips`, `TestRunInstancesRootIopsAndThroughput`, `exerciseRootVolumeType` |
| SigV4 runs before the body is trusted; each S3 failure has its own code. | `TestUnsignedPayloadAndUnreadBody`, `TestSigV4FailuresUseS3ErrorCodes` |
| A resource is the same on every surface. | `internal/surface/interop` |
| Console JSON field names are camelCase. | `tagliatelle` |
| vws-proto comes from a release tag; no local proto tree. | `TestProtoModuleRules` |
| Google Go style. | CI job `lint` |
| Tests pass under the race detector. | CI job `test` |
| `//nolint` names one linter and a reason. | `nolintlint` |
| No swallowed errors. | `errcheck`, `wrapcheck`, `errorlint` |
| Every `resource.Code` has a status and wire code on each surface. | `TestEveryCodeHasAnEC2Error` |
| `NotFound` has each surface's HTTP status. | `TestMissingResourceStatusIsPerSurface` |
| A handler panic is a bare 500. | `TestPanicIsABare500` |
| Ambiguous requests and bad names or sizes are refused before the backend; a key repeated across IAM `Tags` members is last-wins, and a field sent twice is still refused. | `TestMalformedNamesAndBodies`, `TestPolicyTagRepeatedKeyLastWins`, `TestMFADeviceTagRepeatedKeyLastWins` |
| No image assets, branding or vendor API hosts. | `internal/hygiene` |
| No deployment manifests; `publish.yml` is the only release step. | CI job `hygiene` |
| Never push to `main`. | `.githooks/pre-push` |
| Each commit is one logical change that passes tests. | Judgment: `git rebase -x 'go test ./...' origin/main` |
| Structural changes use pstack. | Judgment: the PR names the sketch and verdict |
| The repo is English only. | CI job `english` |

## Working here

- Work in poteto-mode style: short declarative sentences, a minimal diff,
  proof from real artifacts. Use Grok dev bots only, never Cursor cloud
  agents.
- One issue is one branch from `main` and one PR. Commits are atomic and do
  not mix a refactor with a behavior change. Never force-push; never merge
  your own PR.
- Deterministic scripts (the orchestrator, the handoff submit) and bots may
  push branches and open PRs; scripts may also merge. A script merge needs
  every CI check on the head green, verify-gate PASS, the `vws-verify` App
  check run PASS, no conflicts, a squash with `--match-head-commit` set to
  the verified head, and no `blocked` label; `ORCHESTRATE_MERGE=apply` is
  approved only under these conditions. Otherwise only the lead merges.
- The lead (dr eggbot) is woken only for decisions and failures (issue
  scope, real conflicts, failed checks), not for routine push, PR or merge.
  Bots contact the lead only for those, escalations after 3 failures, or
  user approvals; all status lives on GitHub.
- Verify T0 only (unit tests, fakes, envtest); the verification bot runs T1
  and T2.
- pstack, for a new package, shared type, surface or backend method:
  **architect** (caller's usage, then types), **interrogate** (more than one
  reviewer), **correct** (a copied mistake becomes a failing check).
- A new long-running action follows the steps in `docs/rules.md`.
- English only: `scripts/check-english.sh` (CI job `english`) checks files,
  the PR body and commits. Only `.github/english-allowlist` entries
  (`<glob> <reason>`) may hold Hangul.

```sh
go test -race ./...
golangci-lint run
git config core.hooksPath .githooks
go run ./cmd/vws-console-api -backend=fake
e2e/run.sh                                # boto3 e2e, fake backend
VWS_E2E_BACKEND=grpc python3 e2e/e2e.py   # services already running
```

`e2e/e2e.py` prints `skipped(reason)` for a step `VWS_E2E_CAPS` lacks and
ends with `status=PASS|FAIL|INCOMPLETE`; `VWS_E2E_STRICT=1` (set in CI) makes
a skip exit 3.

## /correct loop

1. When a bot is corrected (by the user Su Kim, tmp or eggbot, or by a failed `vws verify`), it opens an issue the same day with the `incident` label using the `.github/ISSUE_TEMPLATE/incident.yml` form. It must fill in the correction and "the check that would have caught this".
2. Every few days vws-verify runs a gardener pass. It groups open incidents by cause and promotes repeated ones to a check (test, lint, guard rule, archtest), not a sentence. The check must actually fail on an input that contains the mistake.
3. When the promoting PR is merged, close the incident with its link. An incident that will not be promoted is closed with the reason.
4. The milestone report (to tmp) lists the number of incidents in the period and the checks promoted.
5. The `incident` label is defined in `.github/labels.yml`, copied from vws-deploy. That file is only a definition and does not create the label on GitHub. `scripts/guard.sh correct` runs `scripts/guard-agents.sh correct`, which checks this section and its body, the required fields of the form and the label definition; `repo-guard.yml` runs it on every pull request and `scripts/guard_test.sh` shows it fails on an empty section.

## Insider-risk guardrails

Bots are insider risks too. The rules below have no exceptions.

1. **Independent verification**: an important result (merge, security, data) is never verified by the bot/model that wrote it. Another bot (or a person) verifies it. (Process rule; CI cannot enforce it.)
2. **Records**: every change leaves a trail of issue → PR (`Part of #N`) → commits. Work logs go in the PR body or issue comments in a form people can read. No force-push or history rewriting (except with the user's approval).
3. **Failure tests**: a new feature is not tested on the happy path only. Include at least one case each for power loss/restart, idempotent re-run and malicious or boundary input, or state in the PR why that is not possible.
4. **Least privilege**: no direct pushes to main. Every change is a single PR from its own branch cut from main. No stacked PRs. No local merges. Tokens are scoped to the repo. RBAC covers only the resources the service code actually calls, as a Role (namespace scope) where possible.
5. **Separated audit**: author bot ≠ verifier bot ≠ merge decision. An author bot never merges its own PR. Merge only when base==main and every CI check on the head commit is success.
6. **Isolation and emergency stop**: a bot/agent is stopped immediately at the user's request or by the orchestrator stopping that bot's session and revoking its token (`gh auth`/PAT revoke). Risky work happens only in a sandbox (the box or a throwaway cluster). No access to production clusters.
7. **Incident disclosure**: rule violations and incidents are never hidden; record them in an issue as `Cause / Impact / Action / Prevention` (label `incident`).
