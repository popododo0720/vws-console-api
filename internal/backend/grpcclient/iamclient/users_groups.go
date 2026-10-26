package iamclient

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"strings"
	"time"

	"cloud.google.com/go/longrunning/autogen/longrunningpb"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	otelcodes "go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// User and group management over vws-iam's UserService and GroupService
// (#314).
//
// Every mutation carries a fresh request_id, which vws-iam replays, so a
// retry on UNAVAILABLE cannot apply a change twice; updates also carry the
// etag they were computed from. Group membership is GroupSpec.members, so
// AddUserToGroup and RemoveUserFromGroup read the group and write the new
// member list under its etag, and read again when another writer won.
// vws-iam cannot rename a user or a group, so UpdateUser and UpdateGroup
// with a new name answer Unimplemented (InvalidAction) once the entity is
// known to exist.

// Limits of the calls that make more than one vws-iam call.
const (
	// OperationTimeout bounds one List scan or membership change when the
	// caller's context has no earlier deadline. Each call inside it keeps
	// CallTimeout.
	OperationTimeout = 30 * time.Second
	// listPageSize is the vws-iam page size of the List scans, its maximum.
	listPageSize = 1000
	// maxListPages bounds one scan: 100,000 users or groups.
	maxListPages = 100
	// membershipAttempts bounds the re-reads of a group whose etag moved
	// while AddUserToGroup or RemoveUserFromGroup wrote it.
	membershipAttempts = 3
)

// tracer names the spans of the user and group calls. Without a registered
// OpenTelemetry SDK they are no-ops.
func tracer() trace.Tracer {
	return otel.Tracer("github.com/popododo0720/vws-console-api/internal/backend/grpcclient/iamclient")
}

func projectName(a resource.AccountID) string { return "projects/" + a.String() }

func userResource(a resource.AccountID, name string) string {
	return projectName(a) + "/users/" + name
}

func groupResource(a resource.AccountID, name string) string {
	return projectName(a) + "/groups/" + name
}

// lastSegment is the user or group name at the end of a resource name.
func lastSegment(resourceName string) string {
	return resourceName[strings.LastIndex(resourceName, "/")+1:]
}

// newRequestID is a random UUID version 4 for one mutation's request_id.
func newRequestID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// observe starts the span of one user or group call and returns the function
// that ends it. A mutation also leaves one structured log record with its
// outcome. Only names reach the span and the log: passwords, secrets and
// policy documents never pass through these calls.
func (a STSAdmin) observe(
	ctx context.Context, action string, mutation bool, account resource.AccountID, user, group string,
) (context.Context, func(error)) {
	return a.observeKey(ctx, action, mutation, account, user, group, nil)
}

// observeKey is observe for an access key call. The span and the log record
// carry the key id *keyID holds when the call ends, never the secret.
func (a STSAdmin) observeKey(
	ctx context.Context, action string, mutation bool, account resource.AccountID, user, group string, keyID *string,
) (context.Context, func(error)) {
	start := time.Now()
	attrs := []attribute.KeyValue{
		attribute.String("rpc.system", "grpc"), attribute.String("rpc.service", "vws.iam.v1"),
		attribute.String("vws.iam.action", action), attribute.String("vws.account", account.String()),
	}
	if user != "" {
		attrs = append(attrs, attribute.String("vws.iam.user_name", user))
	}
	if group != "" {
		attrs = append(attrs, attribute.String("vws.iam.group_name", group))
	}
	ctx, span := tracer().Start(ctx, "vws-iam "+action,
		trace.WithSpanKind(trace.SpanKindClient), trace.WithAttributes(attrs...))
	return ctx, func(err error) {
		outcome := "ok"
		if err != nil {
			outcome = resource.CodeOf(err).String()
			span.SetStatus(otelcodes.Error, outcome)
		}
		span.SetAttributes(attribute.String("vws.iam.outcome", outcome))
		if keyID != nil && *keyID != "" {
			span.SetAttributes(attribute.String("vws.iam.access_key_id", *keyID))
		}
		span.End()
		if !mutation {
			return
		}
		level := slog.LevelInfo
		logAttrs := []slog.Attr{
			slog.String("action", action), slog.String("account", account.String()),
			slog.String("user_name", user), slog.String("group_name", group),
			slog.String("outcome", outcome), slog.Duration("elapsed", time.Since(start)),
		}
		if keyID != nil && *keyID != "" {
			logAttrs = append(logAttrs, slog.String("access_key_id", *keyID))
		}
		if c := resource.CodeOf(err); c == resource.CodeUnavailable || c == resource.CodeInternal {
			level = slog.LevelWarn
			logAttrs = append(logAttrs, slog.String("error", err.Error()))
		}
		a.logger().LogAttrs(ctx, level, "vws-iam user or group change", logAttrs...)
	}
}

// backendUnavailable is a vws-iam outage or timeout: 503 ServiceUnavailable, which
// AWS SDKs retry. The cause stays in the chain for the log.
func backendUnavailable(err error) error {
	e := &resource.Error{Code: resource.CodeUnavailable, Message: "vws-iam is unavailable"}
	return fmt.Errorf("%w: %w", e, err)
}

// entityError maps a vws-iam failure of a user or group call. what is "user"
// or "group" and name the entity the caller named, so NoSuchEntity and
// EntityAlreadyExists carry the AWS wording. A lost etag race is a
// ConcurrentModification (iam.Changed); membership changes read again on it.
func entityError(err error, what, name string) error {
	st, ok := status.FromError(err)
	if !ok {
		return err
	}
	switch st.Code() { //nolint:exhaustive // the rest is authError's.
	case codes.NotFound:
		return iam.EntityNotFound(what, name)
	case codes.AlreadyExists:
		return iam.EntityExists(strings.ToUpper(what[:1])+what[1:], name)
	case codes.Aborted:
		if what == "group" {
			return iam.Changed(iam.GroupChanged)
		}
		return iam.Changed(iam.UserChanged)
	case codes.Unavailable, codes.DeadlineExceeded, codes.Canceled:
		return backendUnavailable(err)
	}
	return authError(err)
}

// opError is the error of a done vws-iam operation, mapped as entityError.
func opError(op *longrunningpb.Operation, what, name string) error {
	switch {
	case op == nil:
		return resource.Internal(errors.New("vws-iam returned no operation"))
	case !op.GetDone():
		return resource.Internal(errors.New("vws-iam returned a running operation"))
	case op.GetError() != nil:
		return entityError(status.ErrorProto(op.GetError()), what, name)
	}
	return nil
}

// entityName reports whether name can be a vws-iam user or group: one
// resource name segment. Anything else addresses another resource and is
// answered as missing without a call.
func entityName(name string) bool {
	return name != "" && !strings.Contains(name, "/")
}

// entityNotFound is the AWS NoSuchEntity answer for a user or group.
func entityNotFound(what, name string) error { return iam.EntityNotFound(what, name) }

// userResourceInAccount reports whether a vws-iam user resource name belongs to
// account.
func userResourceInAccount(account resource.AccountID, resourceName string) bool {
	rest, ok := strings.CutPrefix(resourceName, projectName(account)+"/users/")
	return ok && rest != "" && !strings.Contains(rest, "/")
}

// sameResource reports whether vws-iam answered for the resource asked for.
// vws-iam folds the case of names, so it may spell the name differently.
func sameResource(got, want string) bool { return strings.EqualFold(got, want) }

// userFromProto is the AWS User of a vws-iam user read as resourceName. A
// user outside the caller's account is an internal error.
func userFromProto(account resource.AccountID, u *iamv1.User, resourceName string) (iam.User, error) {
	if !sameResource(u.GetName(), resourceName) || !userResourceInAccount(account, u.GetName()) {
		return iam.User{}, resource.Internal(
			errors.New("vws-iam returned user " + u.GetName() + ", want " + resourceName))
	}
	arn := u.GetStatus().GetArn()
	if !strings.HasPrefix(arn, "arn:vws:iam::"+account.String()+":user/") {
		return iam.User{}, resource.Internal(
			errors.New("vws-iam returned a user outside the caller's account"))
	}
	out := iam.User{Name: lastSegment(u.GetName()), Path: u.GetSpec().GetPath(), ID: u.GetStatus().GetUniqueId(), ARN: arn}
	if out.Path == "" {
		out.Path = "/"
	}
	if t := u.GetCreateTime(); t != nil {
		out.Created = t.AsTime()
	}
	return out, nil
}

// groupFromProto is the AWS Group of a vws-iam group read as resourceName.
func groupFromProto(account resource.AccountID, g *iamv1.Group, resourceName string) (iam.Group, error) {
	prefix := projectName(account) + "/groups/"
	if !sameResource(g.GetName(), resourceName) || !strings.HasPrefix(g.GetName(), prefix) {
		return iam.Group{}, resource.Internal(
			errors.New("vws-iam returned group " + g.GetName() + ", want " + resourceName))
	}
	arn := g.GetStatus().GetArn()
	if !strings.HasPrefix(arn, "arn:vws:iam::"+account.String()+":group/") {
		return iam.Group{}, resource.Internal(
			errors.New("vws-iam returned a group outside the caller's account"))
	}
	out := iam.Group{
		Name: lastSegment(g.GetName()), Path: g.GetSpec().GetPath(), ID: g.GetStatus().GetUniqueId(), ARN: arn,
	}
	if out.Path == "" {
		out.Path = "/"
	}
	if t := g.GetCreateTime(); t != nil {
		out.Created = t.AsTime()
	}
	return out, nil
}

// userFor reads one vws-iam user by resource name. A user outside the
// caller's account is an internal error.
func (a STSAdmin) userFor(ctx context.Context, account resource.AccountID, resourceName string) (iam.User, error) {
	u, err := retry(ctx, a.backoff, a.users.GetUser, &iamv1.GetUserRequest{Name: resourceName})
	if err != nil {
		return iam.User{}, authError(err)
	}
	return userFromProto(account, u, resourceName)
}

// rawUser reads a user for a change: its etag and status ride along.
func (a STSAdmin) rawUser(ctx context.Context, account resource.AccountID, name string) (*iamv1.User, iam.User, error) {
	want := userResource(account, name)
	u, err := retry(ctx, a.backoff, a.users.GetUser, &iamv1.GetUserRequest{Name: want})
	if err != nil {
		return nil, iam.User{}, entityError(err, "user", name)
	}
	out, err := userFromProto(account, u, want)
	return u, out, err
}

// rawGroup reads a group for a change or its members.
func (a STSAdmin) rawGroup(
	ctx context.Context, account resource.AccountID, name string,
) (*iamv1.Group, iam.Group, error) {
	want := groupResource(account, name)
	g, err := retry(ctx, a.backoff, a.groups.GetGroup, &iamv1.GetGroupRequest{Name: want})
	if err != nil {
		return nil, iam.Group{}, entityError(err, "group", name)
	}
	out, err := groupFromProto(account, g, want)
	return g, out, err
}

// --- users ---

// CreateUser implements iam.Admin over UserService.CreateUser. The name and
// path follow the AWS rules the fake applies.
func (a STSAdmin) CreateUser(
	ctx context.Context, account resource.AccountID, name, path string,
) (out iam.User, err error) {
	ctx, end := a.observe(ctx, "CreateUser", true, account, name, "")
	defer func() { end(err) }()
	if err := iam.CheckUserName("userName", name); err != nil {
		return iam.User{}, err
	}
	path, err = iam.NormalizePath("Path", path)
	if err != nil {
		return iam.User{}, err
	}
	op, err := retry(ctx, a.backoff, a.users.CreateUser, &iamv1.CreateUserRequest{
		Parent: projectName(account), UserId: name, RequestId: newRequestID(),
		User: &iamv1.User{Spec: &iamv1.UserSpec{Path: path}},
	})
	if err != nil {
		return iam.User{}, entityError(err, "user", name)
	}
	if err := opError(op, "user", name); err != nil {
		return iam.User{}, err
	}
	created := &iamv1.User{}
	if op.GetResponse() == nil || op.GetResponse().UnmarshalTo(created) != nil {
		return iam.User{}, resource.Internal(errors.New("vws-iam CreateUser returned no user"))
	}
	return userFromProto(account, created, userResource(account, name))
}

// GetUser implements iam.Admin over UserService.GetUser. want must be the
// user's ARN; the zero value sends nothing.
func (a STSAdmin) GetUser(
	ctx context.Context, account resource.AccountID, name string, want iam.AuthorizedPrincipal,
) (iam.User, error) {
	if err := want.Require(); err != nil {
		return iam.User{}, err
	}
	u, err := a.lookupUser(ctx, account, name)
	if err != nil {
		return iam.User{}, err
	}
	if err := want.Bind(u.ARN, iam.UserChanged); err != nil {
		return iam.User{}, err
	}
	return u, nil
}

// ResolveUser implements iam.Resolver over UserService.GetUser: the IAM
// Query surface authorizes on the user's real ARN, path included.
func (a STSAdmin) ResolveUser(ctx context.Context, account resource.AccountID, name string) (iam.Ref, error) {
	u, err := a.lookupUser(ctx, account, name)
	if err != nil {
		return iam.Ref{}, err
	}
	return iam.Ref{ARN: u.ARN, ID: u.ID}, nil
}

// lookupUser reads one user by name; a missing or malformed name is
// NoSuchEntity.
func (a STSAdmin) lookupUser(ctx context.Context, account resource.AccountID, name string) (iam.User, error) {
	if !entityName(name) {
		return iam.User{}, entityNotFound("user", name)
	}
	u, err := a.userFor(ctx, account, userResource(account, name))
	if resource.CodeOf(err) == resource.CodeNotFound {
		return iam.User{}, entityNotFound("user", name)
	}
	return u, err
}

// ListUsers implements iam.Admin over every page of UserService.ListUsers,
// sorted by name and filtered by path prefix ("" is every path). The IAM
// Query surface pages the result with Marker and MaxItems.
func (a STSAdmin) ListUsers(
	ctx context.Context, account resource.AccountID, prefix string,
) (out []iam.User, err error) {
	ctx, end := a.observe(ctx, "ListUsers", false, account, "", "")
	defer func() { end(err) }()
	ctx, cancel := context.WithTimeout(ctx, OperationTimeout)
	defer cancel()
	out = []iam.User{}
	token := ""
	for range maxListPages {
		resp, err := retry(ctx, a.backoff, a.users.ListUsers, &iamv1.ListUsersRequest{
			Parent: projectName(account), PageSize: listPageSize, PageToken: token,
		})
		if err != nil {
			return nil, entityError(err, "user", "")
		}
		for _, u := range resp.GetUsers() {
			got, err := userFromProto(account, u, u.GetName())
			if err != nil {
				return nil, err
			}
			if strings.HasPrefix(got.Path, prefixOrRoot(prefix)) {
				out = append(out, got)
			}
		}
		if token = resp.GetNextPageToken(); token == "" {
			sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
			return out, nil
		}
	}
	return nil, resource.Internal(fmt.Errorf("vws-iam ListUsers has more than %d pages", maxListPages))
}

func prefixOrRoot(p string) string {
	if p == "" {
		return "/"
	}
	return p
}

// UpdateUser implements iam.Admin over UserService.UpdateUser with a mask on
// spec.path and the etag of the user it read. want must be the user's ARN,
// so a change since the caller was authorized is a ConcurrentModification.
// vws-iam cannot rename a user: a new name answers Unimplemented after the
// checks above.
func (a STSAdmin) UpdateUser(
	ctx context.Context, account resource.AccountID, name, newPath, newName string, want iam.AuthorizedPrincipal,
) (err error) {
	ctx, end := a.observe(ctx, "UpdateUser", true, account, name, "")
	defer func() { end(err) }()
	if err := want.Require(); err != nil {
		return err
	}
	if newPath != "" {
		if newPath, err = iam.NormalizePath("newPath", newPath); err != nil {
			return err
		}
	}
	rename := newName != "" && newName != name
	if rename {
		if err := iam.CheckUserName("newUserName", newName); err != nil {
			return err
		}
	}
	if !entityName(name) {
		return entityNotFound("user", name)
	}
	raw, u, err := a.rawUser(ctx, account, name)
	if err != nil {
		return err
	}
	if err := want.Bind(u.ARN, iam.UserChanged); err != nil {
		return err
	}
	if rename {
		return resource.Unimplemented(
			"UpdateUser with NewUserName is not served over vws-iam gRPC: vws-iam cannot rename a user")
	}
	if newPath == "" || newPath == u.Path {
		return nil
	}
	op, err := retry(ctx, a.backoff, a.users.UpdateUser, &iamv1.UpdateUserRequest{
		User:       &iamv1.User{Name: raw.GetName(), Etag: raw.GetEtag(), Spec: &iamv1.UserSpec{Path: newPath}},
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"spec.path"}}, RequestId: newRequestID(),
	})
	if err != nil {
		return entityError(err, "user", name)
	}
	return opError(op, "user", name)
}

// DeleteUser implements iam.Admin over UserService.DeleteUser. It reads the
// user first: want must be its ARN, and the delete carries
// that read's etag, so a user that moved or changed since the caller was
// authorized is a ConcurrentModification and stays. vws-iam refuses while
// the user has access keys, an MFA device, a login profile, a group or a
// policy, which is the AWS DeleteConflict.
func (a STSAdmin) DeleteUser(
	ctx context.Context, account resource.AccountID, name string, want iam.AuthorizedPrincipal,
) (err error) {
	ctx, end := a.observe(ctx, "DeleteUser", true, account, name, "")
	defer func() { end(err) }()
	if err := want.Require(); err != nil {
		return err
	}
	if !entityName(name) {
		return entityNotFound("user", name)
	}
	raw, u, err := a.rawUser(ctx, account, name)
	if err != nil {
		return err
	}
	if err := want.Bind(u.ARN, iam.UserChanged); err != nil {
		return err
	}
	op, err := retry(ctx, a.backoff, a.users.DeleteUser, &iamv1.DeleteUserRequest{
		Name: raw.GetName(), Etag: raw.GetEtag(), RequestId: newRequestID(),
	})
	if err == nil {
		err = opError(op, "user", name)
	} else {
		err = entityError(err, "user", name)
	}
	if !iam.IsChanged(err) && resource.CodeOf(err) == resource.CodeConflict {
		return iam.Conflict(iam.UserDeleteConflict)
	}
	return err
}

// ListGroupsForUser implements iam.Admin from the user's status.groups, each
// read over GroupService.GetGroup. A group deleted since is left out. want
// must be the user's ARN at the read the groups come from.
func (a STSAdmin) ListGroupsForUser(
	ctx context.Context, account resource.AccountID, user string, want iam.AuthorizedPrincipal,
) (out []iam.Group, err error) {
	ctx, end := a.observe(ctx, "ListGroupsForUser", false, account, user, "")
	defer func() { end(err) }()
	if err := want.Require(); err != nil {
		return nil, err
	}
	if !entityName(user) {
		return nil, entityNotFound("user", user)
	}
	ctx, cancel := context.WithTimeout(ctx, OperationTimeout)
	defer cancel()
	raw, u, err := a.rawUser(ctx, account, user)
	if err != nil {
		return nil, err
	}
	if err := want.Bind(u.ARN, iam.UserChanged); err != nil {
		return nil, err
	}
	out = []iam.Group{}
	for _, name := range raw.GetStatus().GetGroups() {
		if !strings.HasPrefix(name, projectName(account)+"/groups/") {
			return nil, resource.Internal(errors.New("vws-iam returned a group outside the caller's account"))
		}
		_, g, err := a.rawGroup(ctx, account, lastSegment(name))
		if resource.CodeOf(err) == resource.CodeNotFound {
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// --- groups ---

// CreateGroup implements iam.Admin over GroupService.CreateGroup.
func (a STSAdmin) CreateGroup(
	ctx context.Context, account resource.AccountID, name, path string,
) (out iam.Group, err error) {
	ctx, end := a.observe(ctx, "CreateGroup", true, account, "", name)
	defer func() { end(err) }()
	if err := iam.CheckGroupName("groupName", name); err != nil {
		return iam.Group{}, err
	}
	path, err = iam.NormalizePath("Path", path)
	if err != nil {
		return iam.Group{}, err
	}
	op, err := retry(ctx, a.backoff, a.groups.CreateGroup, &iamv1.CreateGroupRequest{
		Parent: projectName(account), GroupId: name, RequestId: newRequestID(),
		Group: &iamv1.Group{Spec: &iamv1.GroupSpec{Path: path}},
	})
	if err != nil {
		return iam.Group{}, entityError(err, "group", name)
	}
	if err := opError(op, "group", name); err != nil {
		return iam.Group{}, err
	}
	created := &iamv1.Group{}
	if op.GetResponse() == nil || op.GetResponse().UnmarshalTo(created) != nil {
		return iam.Group{}, resource.Internal(errors.New("vws-iam CreateGroup returned no group"))
	}
	return groupFromProto(account, created, groupResource(account, name))
}

// GetGroup implements iam.Admin over GroupService.GetGroup, with each member
// read over UserService.GetUser. want must be the group's ARN; the zero
// value sends nothing, and a moved group reads no member. A member deleted
// since the group was read is left out.
func (a STSAdmin) GetGroup(
	ctx context.Context, account resource.AccountID, name string, want iam.AuthorizedPrincipal,
) (iam.Group, []iam.User, error) {
	if err := want.Require(); err != nil {
		return iam.Group{}, nil, err
	}
	out, g, err := a.lookupGroup(ctx, account, name)
	if err != nil {
		return iam.Group{}, nil, err
	}
	if err := want.Bind(out.ARN, iam.GroupChanged); err != nil {
		return iam.Group{}, nil, err
	}
	members := make([]iam.User, 0, len(g.GetSpec().GetMembers()))
	for _, m := range g.GetSpec().GetMembers() {
		if !userResourceInAccount(account, m) {
			return iam.Group{}, nil, resource.Internal(
				errors.New("vws-iam GetGroup returned a member outside the caller's account"))
		}
		u, err := a.userFor(ctx, account, m)
		if resource.CodeOf(err) == resource.CodeNotFound {
			continue
		}
		if err != nil {
			return iam.Group{}, nil, err
		}
		members = append(members, u)
	}
	sort.Slice(members, func(i, j int) bool { return members[i].Name < members[j].Name })
	return out, members, nil
}

// ResolveGroup implements iam.Resolver over one GroupService.GetGroup, with
// no member read: the IAM Query surface authorizes on the group's real ARN,
// path included.
func (a STSAdmin) ResolveGroup(ctx context.Context, account resource.AccountID, name string) (iam.Ref, error) {
	g, _, err := a.lookupGroup(ctx, account, name)
	if err != nil {
		return iam.Ref{}, err
	}
	return iam.Ref{ARN: g.ARN, ID: g.ID}, nil
}

// lookupGroup reads one group by name; a missing or malformed name is
// NoSuchEntity.
func (a STSAdmin) lookupGroup(
	ctx context.Context, account resource.AccountID, name string,
) (iam.Group, *iamv1.Group, error) {
	if !entityName(name) {
		return iam.Group{}, nil, entityNotFound("group", name)
	}
	resourceName := groupResource(account, name)
	g, err := retry(ctx, a.backoff, a.groups.GetGroup, &iamv1.GetGroupRequest{Name: resourceName})
	if err != nil {
		if err = authError(err); resource.CodeOf(err) == resource.CodeNotFound {
			return iam.Group{}, nil, entityNotFound("group", name)
		}
		return iam.Group{}, nil, err
	}
	out, err := groupFromProto(account, g, resourceName)
	if err != nil {
		return iam.Group{}, nil, err
	}
	return out, g, nil
}

// ListGroups implements iam.Admin over every page of GroupService.ListGroups,
// sorted by name and filtered by path prefix.
func (a STSAdmin) ListGroups(
	ctx context.Context, account resource.AccountID, prefix string,
) (out []iam.Group, err error) {
	ctx, end := a.observe(ctx, "ListGroups", false, account, "", "")
	defer func() { end(err) }()
	ctx, cancel := context.WithTimeout(ctx, OperationTimeout)
	defer cancel()
	out = []iam.Group{}
	token := ""
	for range maxListPages {
		resp, err := retry(ctx, a.backoff, a.groups.ListGroups, &iamv1.ListGroupsRequest{
			Parent: projectName(account), PageSize: listPageSize, PageToken: token,
		})
		if err != nil {
			return nil, entityError(err, "group", "")
		}
		for _, g := range resp.GetGroups() {
			got, err := groupFromProto(account, g, g.GetName())
			if err != nil {
				return nil, err
			}
			if strings.HasPrefix(got.Path, prefixOrRoot(prefix)) {
				out = append(out, got)
			}
		}
		if token = resp.GetNextPageToken(); token == "" {
			sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
			return out, nil
		}
	}
	return nil, resource.Internal(fmt.Errorf("vws-iam ListGroups has more than %d pages", maxListPages))
}

// UpdateGroup implements iam.Admin over GroupService.UpdateGroup with a mask
// on spec.path and the etag of the group it read. want must be the group's
// ARN, as in UpdateUser. A new name answers Unimplemented
// once the group is known to exist: vws-iam cannot rename.
func (a STSAdmin) UpdateGroup(
	ctx context.Context, account resource.AccountID, name, newPath, newName string, want iam.AuthorizedPrincipal,
) (err error) {
	ctx, end := a.observe(ctx, "UpdateGroup", true, account, "", name)
	defer func() { end(err) }()
	if err := want.Require(); err != nil {
		return err
	}
	if newPath != "" {
		if newPath, err = iam.NormalizePath("newPath", newPath); err != nil {
			return err
		}
	}
	rename := newName != "" && newName != name
	if rename {
		if err := iam.CheckGroupName("newGroupName", newName); err != nil {
			return err
		}
	}
	if !entityName(name) {
		return entityNotFound("group", name)
	}
	raw, g, err := a.rawGroup(ctx, account, name)
	if err != nil {
		return err
	}
	if err := want.Bind(g.ARN, iam.GroupChanged); err != nil {
		return err
	}
	if rename {
		return resource.Unimplemented(
			"UpdateGroup with NewGroupName is not served over vws-iam gRPC: vws-iam cannot rename a group")
	}
	if newPath == "" || newPath == g.Path {
		return nil
	}
	op, err := retry(ctx, a.backoff, a.groups.UpdateGroup, &iamv1.UpdateGroupRequest{
		Group:      &iamv1.Group{Name: raw.GetName(), Etag: raw.GetEtag(), Spec: &iamv1.GroupSpec{Path: newPath}},
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"spec.path"}}, RequestId: newRequestID(),
	})
	if err != nil {
		err = entityError(err, "group", name)
	} else {
		err = opError(op, "group", name)
	}
	if resource.CodeOf(err) == resource.CodeConflict {
		// Not a DeleteConflict: the group changed under the update. A
		// retryable 503 is the closest AWS answer UpdateGroup has.
		return backendUnavailable(err)
	}
	return err
}

// DeleteGroup implements iam.Admin over GroupService.DeleteGroup, reading
// the group first and binding the delete to want and that read's etag,
// as DeleteUser does. vws-iam refuses while the group has members or
// policies (DeleteConflict).
func (a STSAdmin) DeleteGroup(
	ctx context.Context, account resource.AccountID, name string, want iam.AuthorizedPrincipal,
) (err error) {
	ctx, end := a.observe(ctx, "DeleteGroup", true, account, "", name)
	defer func() { end(err) }()
	if err := want.Require(); err != nil {
		return err
	}
	if !entityName(name) {
		return entityNotFound("group", name)
	}
	raw, g, err := a.rawGroup(ctx, account, name)
	if err != nil {
		return err
	}
	if err := want.Bind(g.ARN, iam.GroupChanged); err != nil {
		return err
	}
	op, err := retry(ctx, a.backoff, a.groups.DeleteGroup, &iamv1.DeleteGroupRequest{
		Name: raw.GetName(), Etag: raw.GetEtag(), RequestId: newRequestID(),
	})
	if err == nil {
		err = opError(op, "group", name)
	} else {
		err = entityError(err, "group", name)
	}
	if !iam.IsChanged(err) && resource.CodeOf(err) == resource.CodeConflict {
		return iam.Conflict(iam.GroupDeleteConflict)
	}
	return err
}

// memberIndex is the index of user in members, by name and folded as
// vws-iam compares names, or -1.
func memberIndex(members []string, user string) int {
	return slices.IndexFunc(members, func(m string) bool { return strings.EqualFold(lastSegment(m), user) })
}

// AddUserToGroup implements iam.Admin: GroupService.UpdateGroup on
// spec.members under the etag of the group it read. Adding a member is a
// no-op, and a user already in MaxGroupsPerUser groups is LimitExceeded.
// want binds the change to the group the caller was authorized on
// (changeMembers).
func (a STSAdmin) AddUserToGroup(
	ctx context.Context, account resource.AccountID, group, user string, want iam.AuthorizedPrincipal,
) (err error) {
	ctx, end := a.observe(ctx, "AddUserToGroup", true, account, user, group)
	defer func() { end(err) }()
	change := func(members []string, u *iamv1.User) ([]string, error) {
		if memberIndex(members, user) >= 0 {
			return nil, nil
		}
		if len(u.GetStatus().GetGroups()) >= iam.MaxGroupsPerUser {
			return nil, iam.GroupsPerUserExceeded()
		}
		return append(slices.Clone(members), u.GetName()), nil
	}
	return a.changeMembers(ctx, account, group, user, want, change)
}

// RemoveUserFromGroup implements iam.Admin as AddUserToGroup does. A user
// that is not a member is NoSuchEntity, as in AWS.
func (a STSAdmin) RemoveUserFromGroup(
	ctx context.Context, account resource.AccountID, group, user string, want iam.AuthorizedPrincipal,
) (err error) {
	ctx, end := a.observe(ctx, "RemoveUserFromGroup", true, account, user, group)
	defer func() { end(err) }()
	change := func(members []string, _ *iamv1.User) ([]string, error) {
		i := memberIndex(members, user)
		if i < 0 {
			return nil, entityNotFound("user", user)
		}
		return slices.Delete(slices.Clone(members), i, i+1), nil
	}
	return a.changeMembers(ctx, account, group, user, want, change)
}

// changeMembers reads the group and the user, asks change for the new member
// list (nil: nothing to write) and writes it under the group's etag. When
// another writer moved the etag, or a user or group vanished in between, it
// reads again, up to membershipAttempts times; then it answers a retryable
// ServiceUnavailable. Every read, the first included, must find the group at
// want: a group moved since the caller was authorized is a
// ConcurrentModification, and nothing is written. The zero want is refused
// before any read.
func (a STSAdmin) changeMembers(
	ctx context.Context, account resource.AccountID, group, user string, want iam.AuthorizedPrincipal,
	change func(members []string, u *iamv1.User) ([]string, error),
) error {
	if err := want.Require(); err != nil {
		return err
	}
	if !entityName(group) {
		return entityNotFound("group", group)
	}
	if !entityName(user) {
		return entityNotFound("user", user)
	}
	ctx, cancel := context.WithTimeout(ctx, OperationTimeout)
	defer cancel()
	var lost error
	for range membershipAttempts {
		g, current, err := a.rawGroup(ctx, account, group)
		if err != nil {
			return err
		}
		if err := want.Bind(current.ARN, iam.GroupChanged); err != nil {
			return err
		}
		u, _, err := a.rawUser(ctx, account, user)
		if err != nil {
			return err
		}
		members, err := change(g.GetSpec().GetMembers(), u)
		if err != nil || members == nil {
			return err
		}
		op, err := retry(ctx, a.backoff, a.groups.UpdateGroup, &iamv1.UpdateGroupRequest{
			Group:      &iamv1.Group{Name: g.GetName(), Etag: g.GetEtag(), Spec: &iamv1.GroupSpec{Members: members}},
			UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"spec.members"}}, RequestId: newRequestID(),
		})
		if err == nil {
			err = opError(op, "group", group)
		} else {
			err = entityError(err, "group", group)
		}
		switch resource.CodeOf(err) { //nolint:exhaustive // only a lost race is read again.
		case resource.CodeConflict, resource.CodeNotFound:
			lost = err
			continue
		}
		return err
	}
	return backendUnavailable(fmt.Errorf("group %s kept changing: %w", group, lost))
}
