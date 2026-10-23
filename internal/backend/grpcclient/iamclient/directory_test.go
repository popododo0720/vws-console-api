package iamclient

import (
	"context"
	"encoding/base64"
	"fmt"
	"maps"
	"net"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/longrunning/autogen/longrunningpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"
)

// directory is a stateful vws-iam UserService and GroupService for the #314
// tests. It keeps the vws-iam semantics the client relies on (vws-iam
// 04488bd, internal/grpcapi/users.go and groups.go): names unique with case
// folded, etags checked on update, request_id replayed, DeleteConflict for a
// user in a group and a group with members, members that must exist in the
// same project, names that cannot change, and paged lists.
type directory struct {
	iamv1.UnimplementedUserServiceServer
	iamv1.UnimplementedGroupServiceServer
	iamv1.UnimplementedAccessKeyServiceServer
	iamv1.UnimplementedPolicyServiceServer

	mu     sync.Mutex
	seq    int
	users  map[string]*dirEntity // folded resource name
	groups map[string]*dirEntity
	ops    map[string]dirOp // request_id
	// maxPage caps a List page below vws-iam's 1000, so tests see paging.
	maxPage int
	// failBefore answers UNAVAILABLE that many times per method without
	// applying the call; failAfter applies it and then answers UNAVAILABLE,
	// as when the response is lost.
	failBefore, failAfter map[string]int
	// race is the number of UpdateGroup calls that find the etag moved by
	// another writer.
	race int
	// racePath, when set, is the path that other writer moved the group to.
	racePath string
	// deleteRace is the number of DeleteUser and DeleteGroup calls that find
	// the entity changed by another writer since it was read.
	deleteRace int
	// policyRace is the number of UpdateUser and UpdateGroup calls on the
	// policy fields that find the etag moved by another writer;
	// policyRacePath, when set, is the path that writer moved the entity to.
	policyRace     int
	policyRacePath string
	policies       map[string]*dirPolicy // policy id
	calls          map[string][]proto.Message
	// keys are the access keys by id (#314 bundle 2), as vws-iam 04488bd
	// internal/grpcapi/keys.go and internal/accesskey serve them.
	keys map[string]*dirKey
	// keyState, when set, is the state ListAccessKeys and GetAccessKey report
	// for every key, so tests see INACTIVE and states vws-iam never sends.
	keyState iamv1.AccessKeyState
	// createSecret, when set, replaces the secret CreateAccessKey returns.
	createSecret *string
	// onGetPolicy, when set, runs under d.mu in each GetPolicy, as another
	// writer acting while a list reads the attached policies.
	onGetPolicy func(d *directory)
}

type dirKey struct {
	id, user string // user: the folded user resource name
	created  time.Time
	version  int
}

type dirEntity struct {
	name, path, id string // name: the resource name as created
	created        time.Time
	version        int
	members        []string // groups: user resource names
	attached       []string // policy ids
	inline         map[string]string
}

type dirOp struct {
	method string
	req    []byte
	op     *longrunningpb.Operation
}

var dirNameRE = regexp.MustCompile(`^[A-Za-z0-9+=,.@_-]{1,64}$`)

func newDirectory() *directory {
	return &directory{
		users: map[string]*dirEntity{}, groups: map[string]*dirEntity{}, ops: map[string]dirOp{}, keys: map[string]*dirKey{},
		maxPage: 1000, failBefore: map[string]int{}, failAfter: map[string]int{}, calls: map[string][]proto.Message{},
		policies: map[string]*dirPolicy{},
	}
}

// dirHarness serves a directory over bufconn and returns a client for it.
func dirHarness(t *testing.T) (*Client, *directory) {
	t.Helper()
	d := newDirectory()
	lis := bufconn.Listen(1 << 20)
	g := grpc.NewServer()
	iamv1.RegisterUserServiceServer(g, d)
	iamv1.RegisterGroupServiceServer(g, d)
	iamv1.RegisterAccessKeyServiceServer(g, d)
	iamv1.RegisterPolicyServiceServer(g, d)
	go func() { _ = g.Serve(lis) }()
	t.Cleanup(g.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return New(conn, Options{Backoff: time.Millisecond}), d
}

// sent is a copy of the requests method received.
func (d *directory) sent(method string) []proto.Message {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.calls[method])
}

// enter records req and answers an injected UNAVAILABLE. The caller holds
// d.mu.
func (d *directory) enter(method string, req proto.Message) error {
	d.calls[method] = append(d.calls[method], proto.Clone(req))
	if d.failBefore[method] > 0 {
		d.failBefore[method]--
		return status.Error(codes.Unavailable, "injected")
	}
	return nil
}

// replay answers a request_id seen before: the stored operation for the same
// request, IdempotentParameterMismatch for another; found is false for a new
// request_id. The caller holds d.mu.
func (d *directory) replay(
	method, requestID string, req proto.Message,
) (op *longrunningpb.Operation, found bool, err error) {
	if requestID == "" {
		return nil, false, nil
	}
	prev, ok := d.ops[requestID]
	if !ok {
		return nil, false, nil
	}
	b, _ := proto.MarshalOptions{Deterministic: true}.Marshal(req)
	if prev.method != method || string(prev.req) != string(b) {
		return nil, true, awsErr(codes.Aborted, "IDEMPOTENCY_MISMATCH", "IdempotentParameterMismatch")
	}
	return prev.op, true, nil
}

// done stores and returns a done operation, or answers an injected
// UNAVAILABLE after the change. The caller holds d.mu.
func (d *directory) done(
	method, requestID string, req proto.Message, resp proto.Message,
) (*longrunningpb.Operation, error) {
	op := &longrunningpb.Operation{Name: "operations/" + strconv.Itoa(d.seq), Done: true}
	if resp != nil {
		a, err := anypb.New(resp)
		if err != nil {
			return nil, err
		}
		op.Result = &longrunningpb.Operation_Response{Response: a}
	}
	if requestID != "" {
		b, _ := proto.MarshalOptions{Deterministic: true}.Marshal(req)
		d.ops[requestID] = dirOp{method: method, req: b, op: op}
	}
	if d.failAfter[method] > 0 {
		d.failAfter[method]--
		return nil, status.Error(codes.Unavailable, "injected after the change")
	}
	return op, nil
}

func fold(s string) string { return strings.ToLower(s) }

// split parses projects/P/KIND/ID.
func split(name, kind string) (string, string, error) {
	parts := strings.Split(name, "/")
	if len(parts) != 4 || parts[0] != "projects" || parts[2] != kind || parts[3] == "" {
		return "", "", status.Error(codes.InvalidArgument, "bad name "+name)
	}
	return parts[1], parts[3], nil
}

func (d *directory) nextID(prefix string) string {
	d.seq++
	return fmt.Sprintf("%s%017d", prefix, d.seq)
}

func dirPath(p string) string {
	if p == "" {
		return "/"
	}
	return p
}

func entityARN(project, kind string, e *dirEntity) string {
	return "arn:vws:iam::" + project + ":" + kind + dirPath(e.path) + e.name[strings.LastIndex(e.name, "/")+1:]
}

func (d *directory) userProto(e *dirEntity) *iamv1.User {
	project, _, _ := split(e.name, "users")
	var groups []string
	for _, g := range d.sortedGroups() {
		if slices.ContainsFunc(g.members, func(m string) bool { return fold(m) == fold(e.name) }) {
			groups = append(groups, g.name)
		}
	}
	return &iamv1.User{
		Name: e.name, Etag: strconv.Itoa(e.version), Spec: &iamv1.UserSpec{
			Path: dirPath(e.path), AttachedPolicies: policyNames(project, e.attached), InlinePolicies: maps.Clone(e.inline),
		},
		Status:     &iamv1.UserStatus{Arn: entityARN(project, "user", e), UniqueId: e.id, Groups: groups},
		CreateTime: timestamppb.New(e.created),
	}
}

func (d *directory) groupProto(e *dirEntity) *iamv1.Group {
	project, _, _ := split(e.name, "groups")
	return &iamv1.Group{
		Name: e.name, Etag: strconv.Itoa(e.version),
		Spec: &iamv1.GroupSpec{
			Path: dirPath(e.path), Members: slices.Clone(e.members),
			AttachedPolicies: policyNames(project, e.attached), InlinePolicies: maps.Clone(e.inline),
		},
		Status:     &iamv1.GroupStatus{Arn: entityARN(project, "group", e), UniqueId: e.id},
		CreateTime: timestamppb.New(e.created),
	}
}

func (d *directory) sortedGroups() []*dirEntity {
	out := make([]*dirEntity, 0, len(d.groups))
	for _, g := range d.groups {
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool { return fold(out[i].name) < fold(out[j].name) })
	return out
}

// page is one vws-iam page of the entities under parent, by folded name.
func page[T any](
	d *directory, all map[string]*dirEntity, parent string, size int32, token string, conv func(*dirEntity) T,
) ([]T, string, error) {
	keys := []string{}
	for k := range all {
		if strings.HasPrefix(k, fold(parent)+"/") {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	n := int(size)
	if n <= 0 {
		n = 50
	}
	n = min(n, 1000, d.maxPage)
	start := 0
	if token != "" {
		after, err := base64.RawURLEncoding.DecodeString(token)
		if err != nil {
			return nil, "", status.Error(codes.InvalidArgument, "bad page token")
		}
		start = sort.SearchStrings(keys, string(after)+"\x00")
	}
	end := min(start+n, len(keys))
	out := []T{}
	for _, k := range keys[start:end] {
		out = append(out, conv(all[k]))
	}
	next := ""
	if end < len(keys) {
		next = base64.RawURLEncoding.EncodeToString([]byte(keys[end-1]))
	}
	return out, next, nil
}

func checkPathArg(p string) error {
	if p != "" && !regexp.MustCompile(`^/([\x21-\x7e]{0,510}/)?$`).MatchString(p) {
		return status.Error(codes.InvalidArgument, "bad path")
	}
	return nil
}

// --- UserService ---

func (d *directory) GetUser(_ context.Context, req *iamv1.GetUserRequest) (*iamv1.User, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.enter("GetUser", req); err != nil {
		return nil, err
	}
	if _, _, err := split(req.GetName(), "users"); err != nil {
		return nil, err
	}
	u := d.users[fold(req.GetName())]
	if u == nil {
		return nil, awsErr(codes.NotFound, "NOT_FOUND", "NoSuchEntity")
	}
	return d.userProto(u), nil
}

func (d *directory) ListUsers(_ context.Context, req *iamv1.ListUsersRequest) (*iamv1.ListUsersResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.enter("ListUsers", req); err != nil {
		return nil, err
	}
	us, next, err := page(d, d.users, req.GetParent()+"/users", req.GetPageSize(), req.GetPageToken(), d.userProto)
	if err != nil {
		return nil, err
	}
	return &iamv1.ListUsersResponse{Users: us, NextPageToken: next}, nil
}

func (d *directory) CreateUser(_ context.Context, req *iamv1.CreateUserRequest) (*longrunningpb.Operation, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.enter("CreateUser", req); err != nil {
		return nil, err
	}
	if op, found, err := d.replay("CreateUser", req.GetRequestId(), req); found {
		return op, err
	}
	if !dirNameRE.MatchString(req.GetUserId()) {
		return nil, status.Error(codes.InvalidArgument, "bad user id")
	}
	if err := checkPathArg(req.GetUser().GetSpec().GetPath()); err != nil {
		return nil, err
	}
	name := req.GetParent() + "/users/" + req.GetUserId()
	if d.users[fold(name)] != nil {
		return nil, awsErr(codes.AlreadyExists, "ALREADY_EXISTS", "EntityAlreadyExists")
	}
	u := &dirEntity{
		name: name, path: req.GetUser().GetSpec().GetPath(), id: d.nextID("AIDA"),
		created: time.Now().UTC(), version: 1,
	}
	d.users[fold(name)] = u
	return d.done("CreateUser", req.GetRequestId(), req, d.userProto(u))
}

func (d *directory) UpdateUser(_ context.Context, req *iamv1.UpdateUserRequest) (*longrunningpb.Operation, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.enter("UpdateUser", req); err != nil {
		return nil, err
	}
	if op, found, err := d.replay("UpdateUser", req.GetRequestId(), req); found {
		return op, err
	}
	u := d.users[fold(req.GetUser().GetName())]
	if u == nil {
		return nil, awsErr(codes.NotFound, "NOT_FOUND", "NoSuchEntity")
	}
	d.racePolicies(u, req.GetUpdateMask().GetPaths())
	if e := req.GetUser().GetEtag(); e != "" && e != strconv.Itoa(u.version) {
		return nil, awsErr(codes.Aborted, "ETAG_MISMATCH", "ConcurrentModification")
	}
	project, _, _ := split(u.name, "users")
	spec := req.GetUser().GetSpec()
	next := *u
	for _, p := range req.GetUpdateMask().GetPaths() {
		switch p {
		case "spec.path":
			if err := checkPathArg(spec.GetPath()); err != nil {
				return nil, err
			}
			next.path = spec.GetPath()
		case "spec.attached_policies", "spec.inline_policies":
			if err := d.setPolicies(project, &next, p, spec.GetAttachedPolicies(), spec.GetInlinePolicies()); err != nil {
				return nil, err
			}
		default:
			return nil, status.Error(codes.InvalidArgument, "the directory serves spec.path and the policies only")
		}
	}
	*u = next
	u.version++
	return d.done("UpdateUser", req.GetRequestId(), req, d.userProto(u))
}

func (d *directory) DeleteUser(_ context.Context, req *iamv1.DeleteUserRequest) (*longrunningpb.Operation, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.enter("DeleteUser", req); err != nil {
		return nil, err
	}
	if op, found, err := d.replay("DeleteUser", req.GetRequestId(), req); found {
		return op, err
	}
	u := d.users[fold(req.GetName())]
	if u == nil {
		return nil, awsErr(codes.NotFound, "NOT_FOUND", "NoSuchEntity")
	}
	if d.deleteRace > 0 {
		d.deleteRace--
		u.version++
	}
	if e := req.GetEtag(); e != "" && e != strconv.Itoa(u.version) {
		return nil, awsErr(codes.Aborted, "ETAG_MISMATCH", "ConcurrentModification")
	}
	if len(d.userProto(u).GetStatus().GetGroups()) > 0 || d.keysOf(fold(u.name)) > 0 ||
		len(u.attached) > 0 || len(u.inline) > 0 {
		return nil, awsErr(codes.FailedPrecondition, "DELETE_CONFLICT", "DeleteConflict")
	}
	delete(d.users, fold(req.GetName()))
	return d.done("DeleteUser", req.GetRequestId(), req, nil)
}

// --- GroupService ---

func (d *directory) GetGroup(_ context.Context, req *iamv1.GetGroupRequest) (*iamv1.Group, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.enter("GetGroup", req); err != nil {
		return nil, err
	}
	g := d.groups[fold(req.GetName())]
	if g == nil {
		return nil, awsErr(codes.NotFound, "NOT_FOUND", "NoSuchEntity")
	}
	return d.groupProto(g), nil
}

func (d *directory) ListGroups(_ context.Context, req *iamv1.ListGroupsRequest) (*iamv1.ListGroupsResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.enter("ListGroups", req); err != nil {
		return nil, err
	}
	gs, next, err := page(d, d.groups, req.GetParent()+"/groups", req.GetPageSize(), req.GetPageToken(), d.groupProto)
	if err != nil {
		return nil, err
	}
	return &iamv1.ListGroupsResponse{Groups: gs, NextPageToken: next}, nil
}

func (d *directory) CreateGroup(_ context.Context, req *iamv1.CreateGroupRequest) (*longrunningpb.Operation, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.enter("CreateGroup", req); err != nil {
		return nil, err
	}
	if op, found, err := d.replay("CreateGroup", req.GetRequestId(), req); found {
		return op, err
	}
	if !dirNameRE.MatchString(req.GetGroupId()) {
		return nil, status.Error(codes.InvalidArgument, "bad group id")
	}
	if err := checkPathArg(req.GetGroup().GetSpec().GetPath()); err != nil {
		return nil, err
	}
	name := req.GetParent() + "/groups/" + req.GetGroupId()
	if d.groups[fold(name)] != nil {
		return nil, awsErr(codes.AlreadyExists, "ALREADY_EXISTS", "EntityAlreadyExists")
	}
	g := &dirEntity{
		name: name, path: req.GetGroup().GetSpec().GetPath(), id: d.nextID("AGPA"),
		created: time.Now().UTC(), version: 1,
	}
	d.groups[fold(name)] = g
	return d.done("CreateGroup", req.GetRequestId(), req, d.groupProto(g))
}

func (d *directory) UpdateGroup(_ context.Context, req *iamv1.UpdateGroupRequest) (*longrunningpb.Operation, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.enter("UpdateGroup", req); err != nil {
		return nil, err
	}
	if op, found, err := d.replay("UpdateGroup", req.GetRequestId(), req); found {
		return op, err
	}
	g := d.groups[fold(req.GetGroup().GetName())]
	if g == nil {
		return nil, awsErr(codes.NotFound, "NOT_FOUND", "NoSuchEntity")
	}
	if d.race > 0 {
		d.race--
		g.version++ // another writer got there first
		if d.racePath != "" {
			g.path = d.racePath
		}
	}
	if e := req.GetGroup().GetEtag(); e != "" && e != strconv.Itoa(g.version) {
		return nil, awsErr(codes.Aborted, "ETAG_MISMATCH", "ConcurrentModification")
	}
	d.racePolicies(g, req.GetUpdateMask().GetPaths())
	if e := req.GetGroup().GetEtag(); e != "" && e != strconv.Itoa(g.version) {
		return nil, awsErr(codes.Aborted, "ETAG_MISMATCH", "ConcurrentModification")
	}
	project, _, _ := split(g.name, "groups")
	spec := req.GetGroup().GetSpec()
	for _, p := range req.GetUpdateMask().GetPaths() {
		switch p {
		case "spec.attached_policies", "spec.inline_policies":
			if err := d.setPolicies(project, g, p, spec.GetAttachedPolicies(), spec.GetInlinePolicies()); err != nil {
				return nil, err
			}
		case "spec.path":
			if err := checkPathArg(req.GetGroup().GetSpec().GetPath()); err != nil {
				return nil, err
			}
			g.path = req.GetGroup().GetSpec().GetPath()
		case "spec.members":
			var members []string
			for _, m := range req.GetGroup().GetSpec().GetMembers() {
				mp, _, err := split(m, "users")
				if err != nil {
					return nil, err
				}
				if mp != project {
					return nil, status.Error(codes.InvalidArgument, "member in another project")
				}
				u := d.users[fold(m)]
				if u == nil {
					return nil, awsErr(codes.NotFound, "NOT_FOUND", "NoSuchEntity")
				}
				members = append(members, u.name)
			}
			g.members = members
		default:
			return nil, status.Error(codes.InvalidArgument, "the directory serves spec.path, spec.members and the policies only")
		}
	}
	g.version++
	return d.done("UpdateGroup", req.GetRequestId(), req, d.groupProto(g))
}

func (d *directory) DeleteGroup(_ context.Context, req *iamv1.DeleteGroupRequest) (*longrunningpb.Operation, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.enter("DeleteGroup", req); err != nil {
		return nil, err
	}
	if op, found, err := d.replay("DeleteGroup", req.GetRequestId(), req); found {
		return op, err
	}
	g := d.groups[fold(req.GetName())]
	if g == nil {
		return nil, awsErr(codes.NotFound, "NOT_FOUND", "NoSuchEntity")
	}
	if d.deleteRace > 0 {
		d.deleteRace--
		g.version++
	}
	if e := req.GetEtag(); e != "" && e != strconv.Itoa(g.version) {
		return nil, awsErr(codes.Aborted, "ETAG_MISMATCH", "ConcurrentModification")
	}
	if len(g.members) > 0 || len(g.attached) > 0 || len(g.inline) > 0 {
		return nil, awsErr(codes.FailedPrecondition, "DELETE_CONFLICT", "DeleteConflict")
	}
	delete(d.groups, fold(req.GetName()))
	return d.done("DeleteGroup", req.GetRequestId(), req, nil)
}

// --- AccessKeyService ---

var dirKeyIDRE = regexp.MustCompile(`^AKIA[A-Z2-7]{16}$`)

func (d *directory) keysOf(user string) int {
	n := 0
	for _, k := range d.keys {
		if k.user == user {
			n++
		}
	}
	return n
}

func (d *directory) keyProto(k *dirKey) *iamv1.AccessKey {
	st := iamv1.AccessKeyState_ACCESS_KEY_STATE_ACTIVE
	if d.keyState != iamv1.AccessKeyState_ACCESS_KEY_STATE_UNSPECIFIED {
		st = d.keyState
	}
	return &iamv1.AccessKey{
		Name: d.users[k.user].name + "/accessKeys/" + k.id, Etag: strconv.Itoa(k.version),
		Spec: &iamv1.AccessKeySpec{State: st}, Status: &iamv1.AccessKeyStatus{},
		CreateTime: timestamppb.New(k.created),
	}
}

// keyRef parses projects/P/users/U/accessKeys/ID as vws-iam does: the id
// must be an AKIA key id.
func keyRef(name string) (user, id string, err error) {
	i := strings.LastIndex(name, "/accessKeys/")
	if i < 0 {
		return "", "", status.Error(codes.InvalidArgument, "bad name "+name)
	}
	if _, _, err := split(name[:i], "users"); err != nil {
		return "", "", err
	}
	id = name[i+len("/accessKeys/"):]
	if !dirKeyIDRE.MatchString(id) {
		return "", "", status.Error(codes.InvalidArgument, "bad access key id")
	}
	return fold(name[:i]), id, nil
}

// CreateAccessKey is not an operation and is never replayed: vws-iam keeps
// no plaintext secret, so a lost response means another key.
func (d *directory) CreateAccessKey(
	_ context.Context, req *iamv1.CreateAccessKeyRequest,
) (*iamv1.CreateAccessKeyResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.enter("CreateAccessKey", req); err != nil {
		return nil, err
	}
	if _, _, err := split(req.GetParent(), "users"); err != nil {
		return nil, err
	}
	user := fold(req.GetParent())
	if d.users[user] == nil {
		return nil, awsErr(codes.NotFound, "NOT_FOUND", "NoSuchEntity")
	}
	if d.keysOf(user) >= 2 {
		return nil, awsErr(codes.ResourceExhausted, "QUOTA_EXCEEDED", "LimitExceeded")
	}
	d.seq++
	id := fmt.Sprintf("AKIA%016d", d.seq)
	id = strings.NewReplacer("0", "A", "1", "B", "8", "I", "9", "J").Replace(id[:4]) +
		strings.NewReplacer("0", "A", "1", "B", "8", "I", "9", "J").Replace(id[4:])
	k := &dirKey{id: id, user: user, created: time.Now().UTC().Truncate(time.Second), version: 1}
	d.keys[id] = k
	secret := fmt.Sprintf("%040d", d.seq) // 40 characters, as vws-iam sends
	secret = "s3cr3t" + secret[6:]
	if d.createSecret != nil {
		secret = *d.createSecret
	}
	if d.failAfter["CreateAccessKey"] > 0 {
		d.failAfter["CreateAccessKey"]--
		return nil, status.Error(codes.Unavailable, "injected after the change")
	}
	return &iamv1.CreateAccessKeyResponse{AccessKey: d.keyProto(k), SecretAccessKey: secret}, nil
}

func (d *directory) GetAccessKey(_ context.Context, req *iamv1.GetAccessKeyRequest) (*iamv1.AccessKey, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.enter("GetAccessKey", req); err != nil {
		return nil, err
	}
	user, id, err := keyRef(req.GetName())
	if err != nil {
		return nil, err
	}
	k := d.keys[id]
	if k == nil || k.user != user {
		return nil, awsErr(codes.NotFound, "NOT_FOUND", "NoSuchEntity")
	}
	return d.keyProto(k), nil
}

func (d *directory) ListAccessKeys(
	_ context.Context, req *iamv1.ListAccessKeysRequest,
) (*iamv1.ListAccessKeysResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.enter("ListAccessKeys", req); err != nil {
		return nil, err
	}
	if _, _, err := split(req.GetParent(), "users"); err != nil {
		return nil, err
	}
	user := fold(req.GetParent())
	if d.users[user] == nil {
		return nil, awsErr(codes.NotFound, "NOT_FOUND", "NoSuchEntity")
	}
	ids := []string{}
	for id, k := range d.keys {
		if k.user == user {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	n := int(req.GetPageSize())
	if n <= 0 {
		n = 50
	}
	n = min(n, 1000, d.maxPage)
	start := 0
	if t := req.GetPageToken(); t != "" {
		after, err := base64.RawURLEncoding.DecodeString(t)
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, "bad page token")
		}
		start = sort.SearchStrings(ids, string(after)+"\x00")
	}
	end := min(start+n, len(ids))
	out := &iamv1.ListAccessKeysResponse{}
	for _, id := range ids[start:end] {
		k := d.keyProto(d.keys[id])
		k.Etag = "" // vws-iam lists keys without an etag
		out.AccessKeys = append(out.AccessKeys, k)
	}
	if end < len(ids) {
		out.NextPageToken = base64.RawURLEncoding.EncodeToString([]byte(ids[end-1]))
	}
	return out, nil
}

func (d *directory) DeleteAccessKey(
	_ context.Context, req *iamv1.DeleteAccessKeyRequest,
) (*longrunningpb.Operation, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.enter("DeleteAccessKey", req); err != nil {
		return nil, err
	}
	user, id, err := keyRef(req.GetName())
	if err != nil {
		return nil, err
	}
	if op, found, err := d.replay("DeleteAccessKey", req.GetRequestId(), req); found {
		return op, err
	}
	k := d.keys[id]
	if k == nil || k.user != user {
		return nil, awsErr(codes.NotFound, "NOT_FOUND", "NoSuchEntity")
	}
	if e := req.GetEtag(); e != "" && e != strconv.Itoa(k.version) {
		return nil, awsErr(codes.Aborted, "ETAG_MISMATCH", "ConcurrentModification")
	}
	delete(d.keys, id)
	return d.done("DeleteAccessKey", req.GetRequestId(), req, nil)
}
