# AGENTS.md

The web-only backend of VWS, a private cloud with an AWS-shaped control
plane. One stateless process serves the console JSON API, an EC2 Query entry
point and an S3 REST entry point. Compute, storage and network state lives in
internal services reached over gRPC; this process keeps no copy. The one
record it writes is a RunInstances launch record, a ConfigMap in the
Kubernetes API (#392). Protocol
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
| `internal/backend/launch` | The RunInstances launch record and the tracker that writes it on transitions. |
| `internal/backend/launch/kubestore` | Launch records as ConfigMaps. The only package that sees Kubernetes types. |
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
| Kubernetes types stay in `internal/backend/launch/kubestore`. | depguard `kube-stays-in-kubestore` |
| A RunInstances launch record, a ConfigMap under `-launch-namespace`, holds the client token key, the planned resources and each completed step; it is written only on a step, phase or collection transition, by compare-and-swap on `resourceVersion`, under 256 KiB, and only the latest attempt marks it failed. | `TestRunInstancesRecordsEachStep`, `TestPhaseTransitionsWriteOnce`, `TestPlanNamesACreateWhoseStepWasNotRecorded`, `TestStaleAttemptCannotFailARetry`, `TestNoOpRetryLeavesResourceVersion`, `TestLargestLaunchFitsTheObjectLimit` |
| A failed RunInstances step undoes its attempt last step first, after the record says `undoing` and before the error returns; a retry is the next attempt with new ids, and a cut-short undo is finished by the next request. | `TestFailureAtEveryStepIsUndone`, `TestUndoDeletesInReverseOrder`, `TestCutShortUndoIsFinishedByTheRetry`, `TestUndoNeedsTheRecord`, `TestSuccessAfterAnUndoIsRefused` |
| A RunInstances launch whose process died is resumed by a retry with the same token, or undone by the launch sweep once its record has been `running` or `undoing` with no write for 10 minutes, 20 at once, claimed only while still idle; the bound for a backlog is in `docs/rules.md`. | `TestCrashAfterEveryStepIsResumedOrSwept`, `TestOneSweepUndoesMoreLaunchesThanItRunsAtOnce`, `TestAbandonedIsAnIdleRunningOrUndoingLaunch`, `TestAbandonedLaunchIsUndoneOnce`, `TestAbandonedLaunchWrittenSinceIsLeftAlone`, `TestUnfinishedReadsEveryOpenRecordAcrossPages` |
| The launch GC deletes the plan of each dead attempt (one before the latest, or the latest once `failed`) of a `failed` or `succeeded` launch idle for 10 minutes, then records it collected; it never lists a `running` or `undoing` launch and never deletes a resource of a running, undoing or succeeded attempt. | `TestGCRemovesALateCreateOfAFailedLaunch`, `TestGCKeepsTheSucceededAttempt`, `TestGCNeverTouchesARunningLaunch`, `TestCollectableIsAnIdleEndedLaunchWithADeadAttempt` |
| TerminateInstances clears each Elastic IP association that names an instance of the request before it deletes any of them; compute deletes the delete-on-termination boot volume after it. Each step's request id comes from the client token, so a retry finishes a terminate cut short before its deletes or at a single instance's delete; one cut short between two deletes is #645. | `TestTerminateReleasesTheAddressBeforeTheInstance`, `TestTerminateCutShortIsFinishedByTheRetry`, `TestTerminateOfTwoReleasesBothBeforeEitherDelete`, `backendtest.Run` (`exerciseTerminateRelease`) |
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
| Logs go through the vws-lib obs slog handler; errors go through `report.Error` and `report.Panic` only. A log carries no account id. | `TestRepositoryRules`; `TestAuditLogCarriesNoAccountID` |
| A client `X-Request-Id` is kept only when it is non-empty and at most 64 bytes of `[A-Za-z0-9._:-]`, otherwise the request gets a generated id; public surfaces hide an inbound `traceparent` from the telemetry middleware so a client cannot force sampling, and restore it before the signature check so a signature that covers it still verifies. | `TestClientRequestIDIsValidated`, `TestHTTPMiddlewareStartsARootServerSpan`, `TestSigV4SignedClientHeadersSurviveInboundGuard` |
| One trace holds an inbound HTTP request and its backend gRPC calls; the called service receives the client span in `traceparent` and the request id. | `TestOneTraceCrossesFromHTTPToTheBackend`, `TestClientPropagatesTraceparent` |
| IAM and STS actions validate UserName first, at each action's AWS limit (64 or 128), then authorize on the real ARN; a failed lookup authorizes nothing. | `TestUserNameValidationPrecedesAuthorization`, `TestUserNameLengthFollowsTheAWSLimitOfEachAction`, `TestEntityActionsFailClosedWhenTheLookupFails` |
| IAM and STS response ARN fields and the console `principal` are in the `aws` partition; `PolicyArn`, `RoleArn` and `SerialNumber` take `aws` or `vws` and are authorized as `vws`; a policy document naming `arn:aws:` is `MalformedPolicyDocument` until #681. | `TestIAMAndSTSResponsesUseTheAWSPartition`, `TestOnlyTheAWSPartitionIsReadAsVWS`, `TestDenyOnTheVWSARNHoldsForTheAWSSpelling`, `TestPolicyDocumentNamingTheAWSPartitionIsRefused`, `TestGetCallerIdentityReturnsAWSARNs` |
| Every console route is authenticated and authorized. | `TestEveryRouteIsAuthorized` |
| Console sign-in is rate limited per address and per account user name in bounded tables; a throttle logs no secret; a failed, throttled or locked-out sign-in logs no submitted user name; the session cookie is `__Host-`; a re-login revokes the previous session. | `TestLoginIsRateLimitedPerUserAcrossAddresses`, `TestLimiterMemoryIsBounded`, `TestFailedLoginLogsNoUserName`, `TestLoginLockoutIsPerUserAndIPWithBackoff`, `TestLoginSetsHardenedCookies`, `TestReloginRevokesThePreviousSession`, `TestReloginWithAFailingLogoutSetsNoCookie`, `TestReloginWithAnUnknownCookieSucceeds` |
| Only `iamclient` speaks vws.iam.v1; no secret reaches vws-iam; the `session_context` vws-iam returns goes back to `Authorize` byte for byte and is never logged. | `TestSecretsNeverLeaveConsoleAPI`, `TestSessionContextReachesAuthorizeByteForByte`, `TestSessionContextIsNeverLoggedOrTraced` |
| Named-entity `iam.Admin` methods take an `iam.AuthorizedPrincipal`, built only by `iam.Authorize`. | `TestOnlyTheAuthorizerBuildsAnAuthorizedPrincipal` |
| IAM tag, MFA, access key and policy actions follow AWS and act only on the authorized entity. | `TestAccessKeyCallsActOnTheAuthorizedARN`, `TestEntityPolicyCallsActOnTheAuthorizedARN`, `TestMFADeviceTagSerialValidationPrecedesAuthorization` |
| Access key secrets and policy documents are never logged or traced. | `TestAccessKeySecretIsNeverLoggedOrTraced` |
| Every `resource.Action` has a console route. | `TestEveryActionHasARoute` |
| An unapplied query parameter, filter or subresource is rejected; an EC2 query index is taken only as `strconv.Itoa(n)` spells it. | `TestUnreadQueryFieldsAreRejected`, `TestNonCanonicalIndexIsRejected` |
| Operation names and 500s follow `docs/rules.md`. | `TestOperationLocalServiceNames`, `TestInternalErrorIsLogged` |
| S3 object writes: mask, request id, `If-None-Match`, waiting for the operation. | `TestPutIfNoneMatchIsWriteOnce`, `TestPutObjectWaitsForTheOperation` |
| S3 bucket creates answer as S3 outside us-east-1. | `backendtest.BucketCreate` |
| AuthorizeSecurityGroupIngress takes the `IpPermissions` list, all rules or none; a source VWS cannot store is `UnsupportedOperation`, never dropped. | `TestAuthorizeIngressTakesSeveralPermissions`, `TestUnsupportedIngressSourceIsRefused`, `TestAuthorizeIngressIsAllOrNothing` |
| An ICMP permission is type in FromPort and code in ToPort, -1 or 0 to 255, stored as sent; one without both is `MissingParameter`. A group holds at most 60 inbound rules; past that is `RulesPerSecurityGroupLimitExceeded` and nothing is written. | `TestICMPTypeAndCodeAreChecked`, `TestICMPTypeAndCodeRoundTrip`, `TestRulesPerSecurityGroupLimitExceeded`, `exerciseEC2` |
| EC2 catalog actions are served on both surfaces. | `TestCatalogActionsAreImplemented` |
| EC2 describe calls take boto3's parameter names. | `TestDescribeStandardParameters` |
| EC2 instance, image, volume and address behavior. | `exerciseEC2`, `backendtest.AttachLifecycle` |
| A direct subnet `subnet-direct-<name>` in `vpc-direct` is shared and read-only: every account sees it, tagged `vws:network-type=direct`; a create in it, a delete or a tag is `UnauthorizedOperation`; RunInstances `NetworkInterface.N` may put any device, 0 included, on it, and more than one interface needs one on it; AssociateAddress to a direct primary interface is `InvalidParameterCombination` (#60). | `backendtest.DirectNetworks`, `TestDirectNetworkWritesAreUnauthorizedOperation`, `TestRunInstancesTakesNetworkInterfaces`, `TestRunInstancesRefusesBadNetworkInterfaces`, `TestAssociateAddressRefusesADirectPrimaryInterface` |
| AttachVolume takes only the device names the EC2 User Guide lists as available, any other is `InvalidParameterValue` naming the device before the backend; a client-token detach of a device no detach record can hold is `InvalidParameterValue` before compute (#400). | `TestAttachVolumeDeviceFollowsTheEC2Names`, `TestAttachVolumeRefusesADeviceNameEC2Refuses`, `TestDetachOfADeviceNoRecordCanHoldIsRefused` |
| A volume or block device is `attached` only when compute reports `ATTACHED` on `InstanceStatus.volumes`; no surface defaults to `attached` (#448). | `TestDescribeVolumesFollowsComputeAttachState`, `TestInstanceBlockDeviceStatus`, `backendtest.AttachLifecycle` |
| One bad backend record never fails a listing. | `TestErrorRecordDoesNotFailDescribe`, `TestFailedNetworkRecordDoesNotFailDescribe`, `TestInvalidResourceNameIsSkippedInList`, `TestInvalidCatalogNameIsSkippedInList`, `TestBadReferenceIsSkippedInList` |
| Key pair keys come from `crypto/rand`, are never stored, and names stay unique. | `TestCreatedKeyIsNotDerivedFromTheRequest`, `TestConcurrentCreatesOfOneNameMakeOneKeyPair` |
| A missing resource is `NotFound` of its own kind; an EC2, EBS or VPC resource and an S3 bucket carry the AWS message for that kind, naming the id where AWS does. | `TestMissingResourceKeepsItsKind`, `TestNotFoundMessagesMatchAWS`, `TestNoSuchBucketMessagesMatchAWS` |
| A malformed instance ID is `InvalidInstanceID.Malformed` on every EC2 action that takes one; a tagging call's malformed `ResourceId` is `InvalidID`. | `TestMalformedInstanceIDIsInvalidInstanceIDMalformed`, `TestCreateTagsMalformedResourceIDIsInvalidID` |
| A `DetachVolume` retry returns the first detach, within the label budget. Its four known limits wait on vws-proto#57, for the reasons in `docs/rules.md` (#317). | `backendtest.DetachReplay`, `backendtest.DetachWindow` |
| A `DetachVolume` client token lives for `backend.ClientTokenWindow`, 24 hours, the vws-compute `request_id` window (`vws/common/v1/operation.proto`, "A request_id is remembered for 24 hours"). Over gRPC its replay records are pruned on that window (`backend.ClientTokenExpired`: past the window and `backend.ClientTokenGrace`); what a retry after it answers is in `docs/rules.md` (#305). | `backendtest.DetachWindow`, `TestPruneDetachRecords` |
| A `DetachVolume` saved operation is bound to its request by a 64-bit token, `sha256(request id, fingerprint)[:8]` as 16 hex digits, and is not widened (#304). A collision only matters for two parameter sets sent with one client token, and the token is bound to the request id, which is derived from the account and the client token, so only that caller can make one. Because the caller picks both parameter sets, a wider token does not stop a deliberate collision: the 22 hex digits left beside a 40-digit operation id in a 63-byte label value still give 88 bits, about 2^44 hashes by the birthday bound. The worst outcome is that caller's own earlier detach coming back instead of `IdempotentParameterMismatch`, with no other account or volume affected. An accidental collision is about 2^-64 per pair within the 24-hour token window. Widening would add a second token format to read for no gain. | `TestDetachOpTokenRules` |
| The detach recovery path matches `docs/formal/detach.tla` (pstack `create-formal-verification-skill` 0.15.30). | CI workflow `tla` (job `detach`) |
| IAM authorize, then read or write, matches `docs/formal/iamauth.tla`. | CI workflow `tla-iam` (job `iam`) |
| Volume types map one to one; an unknown type is refused. | `TestVolumeTypeRefusesUnknown` |
| ModifyVolume refuses every explicit Size on a volume already above its type's EC2 maximum: EC2 takes a target at least the existing size and within the current type's limits, so the volume has no valid target, not even its current size (#436). | `TestModifyRefusesSizeAboveTypeMaximum`, `TestModifyVolumeAboveTypeMaximumNeverReachesStorage` |
| One ModifyVolume is one storage `UpdateVolume` whose mask names exactly the Size, VolumeType, Iops and Throughput it sets (vws-storage#87); the target follows the EC2 type-change defaults and per-type rules, checked against the target type and size together before the backend. | `TestModifyChangesTypeAndPerformance`, `TestModifyRefusesAnIllegalTarget`, `TestModifyVolumeSendsOneMaskWithTheNamedFields`, `TestModifyVolumeTakesTypeIopsAndThroughput`, `backendtest.Run` (`exerciseVolumeTypes`) |
| RunInstances creates the root volume with the root device mapping's type (gp2 when omitted), Ebs.VolumeSize (the image size, at least 8 GiB, when omitted), Ebs.Iops and Ebs.Throughput under the CreateVolume per-type rules, with the gp3 defaults when omitted; a size below the image is `InvalidBlockDeviceMapping` before anything is created (an image of unknown size is #660); any other device mapping is an extra volume, and `Ebs.SnapshotId` (#675), `Ebs.Encrypted=true` and `Ebs.KmsKeyId` (#676), `VirtualName` (#677) and `NoDevice` (#678) are `UnsupportedOperation` naming the field and the reason. | `TestRunInstancesRootVolumeTypeRoundTrips`, `TestRunInstancesRootIopsAndThroughput`, `TestRunInstancesRootVolumeSizeRoundTrips`, `TestRunInstancesBlockDeviceMappingRefusals`, `TestRootVolumeBelowARegisteredImageIsRefused`, `TestRootVolumeFollowsASeededImageSize`, `TestConsoleRootVolumeSizeFollowsTheImage`, `TestRootIopsRatioFollowsTheRootSize`, `TestRootIopsRatioIsCheckedOnTheImageSize`, `TestUnsupportedBlockDeviceFieldsAreRefusedWithAReason`, `exerciseRootVolumeType`, `exerciseRootVolumeSize` |
| RunInstances takes the root mapping's `Ebs.DeleteOnTermination`, `true` or `false` in any case, anything else `InvalidParameterValue`; it reads back on the block device and the volume attachment, and a kept root is available once its instance terminates, and its DetachVolume is `VolumeNotInUse`. Over gRPC a launch that keeps its root is undone and refused as `UnsupportedOperation` unless compute reports the boot attachment's `delete_on_termination` false (vws-compute#173). | `TestRunInstancesRootDeleteOnTerminationRoundTrips`, `TestRunInstancesRootDeleteOnTerminationRefusals`, `TestConsoleRootVolumeKeptRoundTrips`, `TestKeptRootNeedsAComputeThatKeepsIt`, `TestKeptRootLaunchIsResumedByTheRetry`, `TestKeptRootIsUndone`, `TestDefaultRootLeavesDeleteOnTerminationUnset`, `TestRootVolumeReadsComputesDeleteOnTermination`, `TestKeptRootOfATerminatedInstanceIsNotInUse`, `exerciseRootDeleteOnTermination` |
| RunInstances takes each non-root mapping as a blank volume per instance at its device, after the root in index order, under the CreateVolume per-type rules with `Ebs.VolumeSize` required; more than 26 beside the root is `AttachmentLimitExceeded`, and a device the EC2 User Guide does not list, one mapped twice or the root (`xvda` too) is `InvalidBlockDeviceMapping`. Its `Ebs.DeleteOnTermination`, `true` when omitted, reads back and holds on terminate. Over gRPC each is a planned launch step created before its instance, attached with `delete_on_termination` set, and a launch whose default extra volume compute reads back kept is undone and refused as `UnsupportedOperation` (vws-compute#173). | `TestExtraVolumesAreChecked`, `TestRunInstancesExtraVolumesRoundTrip`, `TestRunInstancesExtraVolumeRefusals`, `TestConsoleExtraVolumesRoundTrip`, `TestExtraVolumesArePlannedAndCreatedPerIndex`, `TestExtraDeleteOnTerminationNeedsAComputeThatHonorsIt`, `TestExtraVolumeFailureAtEveryStepIsUndone`, `TestExtraVolumeCrashAfterEveryStepIsResumedOrSwept`, `TestGCRemovesALateExtraVolumeOfAFailedLaunch`, `exerciseLaunchExtraVolumes` |
| SigV4 runs before the body is trusted; each S3 failure has its own code. | `TestUnsignedPayloadAndUnreadBody`, `TestSigV4FailuresUseS3ErrorCodes` |
| A resource is the same on every surface. | `internal/surface/interop` |
| Console JSON field names are camelCase. | `tagliatelle` |
| vws-proto comes from a release tag; no local proto tree. | `TestProtoModuleRules` |
| Google Go style. | CI job `lint` |
| Tests pass under the race detector. | CI job `test` |
| `//nolint` names one linter and a reason. | `nolintlint` |
| No swallowed errors. | `errcheck`, `wrapcheck`, `errorlint` |
| Every `resource.Code` has a status and wire code on each surface. | `TestEveryCodeHasAnEC2Error` |
| EC2 requests are rate limited per account and IAM action with EC2's bucket classes (describe 100/20 s, mutate 50/5 s, RunInstances and StartInstances 5/2 s), set by `-ec2-<class>-burst` and `-ec2-<class>-rate`; over the limit EC2 Query is 503 `RequestLimitExceeded`, the console 429 with `Retry-After`, and nothing reaches vws-iam or a backend. | `TestRequestLimitExceededIsAWSShaped`, `TestBucketsArePerAccountAndAction`, `TestConsoleSharesTheEC2RequestLimit` |
| RunInstances runs inside an in-flight launch cap, per process: 20 instances per account, 100 in all, 200 waiting launches, a 10 s wait (`-launch-inflight-per-account`, `-launch-inflight-global`, `-launch-queue`, `-launch-queue-wait`); room goes in queue order, a waiter over its account's cap is skipped so an account at its cap never holds up another, the first waiter held back only by the global cap reserves the global room so small launches cannot starve a large one, and a launch past the queue or the wait, or whose caller went away, is 503 `RequestLimitExceeded` over EC2 Query, 429 on the console, creating nothing (#393). | `TestOneAccountCannotStarveAnother`, `TestLargeLaunchReservesTheGlobalRoom`, `TestQueueBoundRefusesAtOnce`, `TestWaitTimeoutRefusesAndLeaksNothing`, `TestCancelRacingAGrantLeaksNothing`, `TestLaunchCapRefusesAnInFlightAccount`, `TestBadLaunchLimitsAreRejected` |
| A RunInstances flood from one account delays no other account: with the default limits, while A sends 200 launches and its admitted ones stay in the backend, B's 5 launches are answered within 2 s plus their own backend time, before any queued launch of A; the general bound is in `docs/rules.md` (#393). | `TestQuietAccountLaunchesWithinTheBoundDuringAFlood` |
| `NotFound` has each surface's HTTP status; a vws-iam `InvalidClientTokenId` is HTTP 403 even on gRPC `NOT_FOUND`. | `TestMissingResourceStatusIsPerSurface`, `TestInvalidClientTokenIDIsHTTP403` |
| Over gRPC a resource's user tags take at most 58 compute labels (64 less 6 reserved, fewer beside detach records): a tag that is a valid label takes one, the rest are packed as JSON into labels of 63 bytes; past that, tags EC2 allows are `TagLimitExceeded` with the reason, and nothing is written (#398). | `TestPackedTagBudget`, `TestCreateTagsAtThePackedBudget`, `TestCreateTagsOverTheBudgetIsTagLimitExceeded`, `TestTagLimitExceededCode` |
| DeleteTags follows EC2 on instances, VPCs and subnets: a key alone deletes the tag whatever its value, a key with a value (empty included) only on a match, no `Tag.N` deletes every user tag and keeps `aws:` ones; no request may set or name an `aws:` key; the console refuses a JSON `null` selector; each kind of a CreateTags or DeleteTags is checked before any kind is written; a tag write over gRPC keeps internal labels and never rewrites tags that do not decode. | `TestDeleteTags`, `TestRemoveTags`, `TestDeleteTagsRequestNormalize`, `TestAWSTagKeysCannotBeSet`, `TestRequestTagsRefuseAWSKeys`, `TestFannedOutTagRequestIsCheckedBeforeAnyWrite`, `TestVpcAndSubnetTags`, `TestUntagVpcsWritesNothingWhenALaterVpcDoesNotDecode`, `TestConsoleAndQueryDeleteTheSameTags`, `backendtest.Run` |
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
