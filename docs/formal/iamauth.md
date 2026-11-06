# Formal model: IAM authorize, then read or write

`iamauth.tla` is a TLA+ model of how an IAM Query action on a named user,
group or role reads or writes it only at the ARN `iam.Authorize` approved
(#373, the #331 family). It checks every interleaving of two concurrent
requests, another admin moving the entity to a denied path and back, and a
console-api restart at any step.

Run it with `scripts/tla-iam.sh` (needs Java 11+; a few seconds). CI runs it
in `.github/workflows/tla-iam.yml`.

Last confirmed against the code at commit `1457055`. When a file in
"Coverage" changes after that commit, read the change against the model
before trusting a pass, and move this commit forward only once the model
describes the new code.

## What is modeled

| Model | Code |
| --- | --- |
| `arn`, `etag` | the entity's ARN (its path) and the vws-iam etag every write of it changes |
| `Auth` | `iam.Resolver` then `iam.Authorize` (`internal/surface/iamquery/iamquery.go`, `actions.go`); a failed lookup answers an error (#358) |
| `want` | the `iam.AuthorizedPrincipal`, built only by `iam.Authorize` (`internal/iam/authorized.go`) |
| `Bind`, `Bound` | the first read of the Admin call and `AuthorizedPrincipal.Bind`: `GetUser`, `rawUser`, `boundUser`, `keyUser`, `roleAt`, `policyHolder` |
| `Page`, `Verify` | the device or key pages of `ListMFADevices` and `ListAccessKeys`, then `unchangedUser` (#407) |
| `Write` | the write RPC: under the bound read's etag, with `expected_user_arn`, or with no precondition |
| `Undo` | `undoEnableMFADevice` |
| `Move` | another admin's `UpdateUser` or `UpdateGroup` `NewPath`, or a role deleted and created again on another path |
| `Restart` | a console-api restart: every running request is lost where it stands |

The gRPC Admin calls are in `internal/backend/grpcclient/iamclient`. Each
modeled action stands for the code path it takes (`Shape` in the spec):

| Shape | Action modeled | Others of the same shape |
| --- | --- | --- |
| `read`: the entity's data all comes from the bind read | `GetUser` | `GetGroup`, `GetRole`, `ListGroupsForUser`, the user and group policy reads |
| `pages`: bind, pages, etag reread | `ListAccessKeys` | `ListMFADevices` |
| `cas`: write under the bound etag | `UpdateUser` | `DeleteUser`, `UpdateGroup`, `DeleteGroup`, group membership, user and group policy writes |
| `expect`: write with `expected_user_arn` | `UpdateAccessKey` | `DeleteAccessKey` |
| `undo`: write, etag reread, undo | `EnableMFADevice` | |
| `none`: write with no precondition | `CreateAccessKey`, `UpdateRole` | `UpdateRoleDescription` |

A `read` call may make more RPCs after the bind read, but they read other
resources: `ListGroupsForUser` reads each group the user's status names, and
`ListAttachedUserPolicies` reads each managed policy the bound read lists,
then binds the user again. The entity's own data (its groups, its attached
and inline policies) is the bind read's, so a move after it changes nothing
the call returns.

The fake backend (`internal/iam/store.go`) binds and acts under one lock, so
there every call is one step and cannot break these properties.

## Properties

| Property | Plain meaning | Code it guards | Seeded bug that breaks it |
| --- | --- | --- | --- |
| `DenyIsNeverSkipped` | A failed lookup authorizes nothing: no request is allowed while the entity's real ARN is denied. `Bind` would then refuse the guessed principal too, so this guards the decision, not the data. | `spec.resource` sets `resourceErr` (`iamquery.go`) | `FixFailClosed=FALSE`: authorize the path-less ARN, which a Deny on the real path misses |
| `ReadsBound` | A one-call read returns data only of the entity at the authorized ARN. | `AuthorizedPrincipal.Bind` on every entity read (#331, #342) | `FixBind=FALSE`: read by name |
| `PagesBound` | A read of several calls returns no page read while the entity was elsewhere, a move away and back included. | `unchangedUser` compares the etag (#407) | `FixPageEtag=FALSE`: the reread checks the ARN only |
| `WritesBound` | A guarded write never applies to the entity at another ARN. | the etag on `UpdateUser` and `UpdateGroup`; `expected_user_arn` on access key writes (#340) | `FixWriteEtag=FALSE` or `FixExpectARN=FALSE` |
| `UndoCatchesMoves` | An `EnableMFADevice` that answers leaves no enable made at another ARN. | `EnableMFADevice`'s `unchangedUser` and `undoEnableMFADevice` | `FixUndoEtag=FALSE`: the reread checks the ARN only |

`scripts/tla-iam.sh` checks the real design (every `Fix*` TRUE) with all
properties, then each seeded bug against the property it guards, and fails
unless each seeded bug produces a counterexample.

The ABA read, as TLC finds it with `FixPageEtag=FALSE` (8 states): a
`ListAccessKeys` is authorized and binds the user at `ok`; the user moves to
`deny`; a key page is read; the user moves back to `ok`; the reread sees
`ok` and the call answers the page it read at `deny`.

## Findings in the current code

Each fails on the real design. `scripts/tla-iam.sh` keeps them in its list
and fails once one holds, so a fix shows up as a failing CI step; the
property then moves into `iamauth.cfg`.

1. `CreateAccessKeyBound`: `CreateAccessKey` binds the user with `keyUser`,
   then sends `CreateAccessKeyRequest`, which has no `expected_user_arn` or
   etag in vws-proto, and does not read the user again. A user moved to a
   denied path in between gets the key, and the caller gets its secret
   (5 states).
2. `UpdateRoleBound`: `UpdateRole` and `UpdateRoleDescription` bind the role
   with `roleAt`, then send `UpdateRoleRequest` without the role's etag. A
   role deleted and created again on a denied path in between is changed
   (5 states). `UpdateRoleRequest.role` already carries `Role.etag` in
   vws-proto.
3. `EnableNeverStaysUnverified`: `EnableMFADevice` enables the device first
   and checks the user after. A restart between the enable and the check
   (or an undo whose outcome is unknown, which the code already answers as
   an internal error) leaves the device enabled for a user at a denied path
   (6 states). `EnableMfaDeviceRequest` has no precondition on the user.

## Bounds and assumptions

- 2 requests, every pair of the 7 modeled actions, one allowed ARN, one
  denied ARN.
- Up to 2 moves per run (a move away and back) and 1 restart.
- A paged read reads 2 pages.
- Real design result: 18,081 distinct states, 0 violations, depth 13.

## Not modeled

- Retries after a restart: a retry is a new request, authorized again.
- The zero `AuthorizedPrincipal` (an action without its ARN member): every
  Admin method refuses it with `Require` before any read. The compiler and
  `TestOnlyTheAuthorizerBuildsAnAuthorizedPrincipal` keep that, not TLC.
- `UpdateUser` and `UpdateGroup` authorizing the target ARN too
  (`authorizeMovedUser`, `authorizeMovedGroup`).
- The undo itself racing a concurrent enrollment of the same device
  (vws-proto#125), and MFA device, policy and session state.
- The bounded retry loops of membership and policy writes.

## Coverage

`internal/iam/authorized.go` (`Authorize`, `Bind`, `Require`),
`internal/surface/iamquery/iamquery.go` and `actions.go` (lookup, then
`iam.Authorize`), `internal/backend/grpcclient/iamclient/users_groups.go`
(`GetUser`, `UpdateUser`, `boundUser` callers), `access_keys.go`
(`CreateAccessKey`, `ListAccessKeys`, `UpdateAccessKey`, `DeleteAccessKey`),
`admin.go` (`boundUser`, `unchangedUser`, `roleAt`, `UpdateRole`,
`EnableMFADevice`, `ListMFADevices`), `policies.go` (`policyHolder`,
`writeHolder`).
