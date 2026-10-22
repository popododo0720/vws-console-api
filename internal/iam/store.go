package iam

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// Limits from AWS IAM quotas that the fake enforces.
const (
	maxAccessKeysPerUser = 2
	maxAttachedPerEntity = 10
	maxGroupsPerUser     = 10
	maxPolicyVersions    = 5
	minSession           = 15 * time.Minute
	defaultMaxSession    = 3600
	maxMaxSession        = 43200
)

var (
	entityName  = regexp.MustCompile(`^[\w+=,.@-]{1,64}$`)
	groupName   = regexp.MustCompile(`^[\w+=,.@-]{1,128}$`)
	policyName  = regexp.MustCompile(`^[\w+=,.@-]{1,128}$`)
	sessionName = regexp.MustCompile(`^[\w+=,.@-]{2,64}$`)
	pathRule    = regexp.MustCompile(`^/([\x21-\x7E]*/)?$`)
)

type store struct {
	users    map[string]*userRec
	groups   map[string]*groupRec
	roles    map[string]*roleRec
	policies map[string]*policyRec    // by ARN
	mfa      map[string]*mfaDeviceRec // by serial number
}

// mfaDeviceRec is a virtual MFA device in the fake. The device keeps its tags
// and the user it is enabled for. A device is reachable only after
// AddMfaDevice.
type mfaDeviceRec struct {
	// tags are the AWS tags of the device, keyed by tag key. AWS tag keys are
	// case sensitive for a virtual MFA device, so the map is not folded.
	tags map[string]string
	// user is the name of the user the device is enabled for. Empty when the
	// device is unassigned.
	user       string
	enableTime time.Time
}

type holder struct {
	attached map[string]bool // policy ARNs
	inline   map[string]string
	parsed   map[string][]policyStatement
}

func newHolder() holder {
	return holder{attached: map[string]bool{}, inline: map[string]string{}, parsed: map[string][]policyStatement{}}
}

type userRec struct {
	User
	holder
	groups map[string]bool
	keys   map[string]bool
	login  *loginRec
}

type groupRec struct {
	Group
	holder
	members map[string]bool
}

type roleRec struct {
	Role
	holder
	trust []policyStatement
}

type policyVersionRec struct {
	PolicyVersion
	parsed []policyStatement
}

type policyRec struct {
	ManagedPolicy
	versions []policyVersionRec
	// nextVersion counts every version ever created, so a deleted id is not
	// reused, as vws-iam does.
	nextVersion int
	// tags are the AWS tags of the policy, keyed by tag key. AWS policy tag
	// keys are case sensitive, so the map is not folded.
	tags map[string]string
}

// current is the default version. The caller holds f.mu.
func (p *policyRec) current() *policyVersionRec {
	for i := range p.versions {
		if p.versions[i].ID == p.DefaultVersion {
			return &p.versions[i]
		}
	}
	return nil
}

// statements are the default version's parsed statements. The caller holds
// f.mu.
func (p *policyRec) statements() []policyStatement {
	if v := p.current(); v != nil {
		return v.parsed
	}
	return nil
}

func notFound(what, name string) error {
	return &resource.Error{Code: resource.CodeNotFound, Message: "The " + what + " with name " + name + " cannot be found."}
}

func exists(what, name string) error {
	return &resource.Error{Code: resource.CodeAlreadyExists, Message: what + " with name " + name + " already exists."}
}

func conflict(msg string) error { return &resource.Error{Code: resource.CodeConflict, Message: msg} }

func quota(msg string) error {
	return &resource.Error{Code: resource.CodeResourceExhausted, Message: msg}
}

func checkName(rule *regexp.Regexp, field, v string) error {
	if !rule.MatchString(v) {
		return resource.Invalid(field, "1 validation error detected: Value '"+v+"' at '"+field+"' failed to satisfy constraint")
	}
	return nil
}

func normPath(p string) (string, error) { return normPathAs(p, "Path") }

func normPathAs(p, field string) (string, error) {
	if p == "" {
		return "/", nil
	}
	if len(p) > 512 || !pathRule.MatchString(p) {
		return "", resource.Invalid(field, "The specified value for path is invalid. "+
			"It must begin and end with / and contain only alphanumeric characters and/or / characters.")
	}
	return p, nil
}

// randID is prefix plus n characters of the IAM id alphabet.
func randID(prefix string, n int) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	b := make([]byte, n)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return prefix + string(b)
}

func randSecret(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func (f *Fake) account(a resource.AccountID) *store {
	st := f.accounts[a]
	if st == nil {
		st = &store{
			users: map[string]*userRec{}, groups: map[string]*groupRec{}, roles: map[string]*roleRec{},
			policies: map[string]*policyRec{}, mfa: map[string]*mfaDeviceRec{},
		}
		f.accounts[a] = st
	}
	return st
}

// AddMfaDevice registers an unassigned virtual MFA device so it can be listed
// and its tags managed, and returns its serial number (the AWS SerialNumber).
// It is for tests and for a fake seeded with the devices of an account: the
// IAM Query surface does not create MFA devices yet.
func (f *Fake) AddMfaDevice(a resource.AccountID, name string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	st := f.account(a)
	serial := iamARN(a, "mfa", "/", name)
	st.mfa[serial] = &mfaDeviceRec{tags: map[string]string{}}
	return serial
}

// AssignMfaDevice enables a virtual MFA device for a user of the same account
// so ListVirtualMFADevices reports it as assigned. A zero enableTime means the
// fake's now. It is for tests and for a fake seeded with the devices of an
// account.
func (f *Fake) AssignMfaDevice(a resource.AccountID, serial, user string, enableTime time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	st := f.account(a)
	d, err := st.mfaDevice(serial)
	if err != nil {
		return err
	}
	if st.users[user] == nil {
		return notFound("user", user)
	}
	if enableTime.IsZero() {
		enableTime = f.now()
	}
	d.user = user
	d.enableTime = enableTime.UTC()
	return nil
}

func iamARN(a resource.AccountID, kind, path, name string) string {
	return "arn:vws:iam::" + a.String() + ":" + kind + path + name
}

// statementsFor collects the identity policies of a user or assumed-role ARN.
// The caller holds f.mu.
func (st *store) statementsFor(arn string) []policyStatement {
	var out []policyStatement
	add := func(h holder) {
		for _, s := range h.parsed {
			out = append(out, s...)
		}
		for p := range h.attached {
			if rec := st.policies[p]; rec != nil {
				out = append(out, rec.statements()...)
			}
		}
	}
	if role, ok := assumedRoleName(arn); ok {
		if r := st.roles[role]; r != nil {
			add(r.holder)
		}
		return out
	}
	for _, u := range st.users {
		if u.ARN != arn {
			continue
		}
		add(u.holder)
		for g := range u.groups {
			if gr := st.groups[g]; gr != nil {
				add(gr.holder)
			}
		}
	}
	return out
}

// assumedRoleName reads arn:vws:sts::<account>:assumed-role/<role>/<session>.
func assumedRoleName(arn string) (string, bool) {
	_, rest, ok := strings.Cut(arn, ":assumed-role/")
	if !ok || !strings.HasPrefix(arn, "arn:vws:sts::") {
		return "", false
	}
	role, _, ok := strings.Cut(rest, "/")
	return role, ok
}

// --- users ---

// CreateUser implements Admin.
func (f *Fake) CreateUser(_ context.Context, a resource.AccountID, name, path string) (User, error) {
	if err := checkName(entityName, "userName", name); err != nil {
		return User{}, err
	}
	if strings.EqualFold(name, RootUserName) {
		return User{}, resource.Invalid("userName", "the user name "+RootUserName+" is reserved for the account root")
	}
	path, err := normPath(path)
	if err != nil {
		return User{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	st := f.account(a)
	if st.users[name] != nil {
		return User{}, exists("User", name)
	}
	u := User{Name: name, Path: path, ID: randID("AIDA", 17), ARN: iamARN(a, "user", path, name), Created: f.now()}
	st.users[name] = &userRec{User: u, holder: newHolder(), groups: map[string]bool{}, keys: map[string]bool{}}
	return u, nil
}

// GetUser implements Admin.
func (f *Fake) GetUser(_ context.Context, a resource.AccountID, name string) (User, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	u := f.account(a).users[name]
	if u == nil {
		return User{}, notFound("user", name)
	}
	return u.User, nil
}

// ListUsers implements Admin.
func (f *Fake) ListUsers(_ context.Context, a resource.AccountID, prefix string) ([]User, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := []User{}
	for _, u := range f.account(a).users {
		if strings.HasPrefix(u.Path, prefixOr(prefix)) {
			out = append(out, u.User)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func prefixOr(p string) string {
	if p == "" {
		return "/"
	}
	return p
}

// DeleteUser implements Admin. Like AWS it refuses while the user still has
// access keys, policies, group memberships, a login profile or an assigned MFA
// device.
func (f *Fake) DeleteUser(_ context.Context, a resource.AccountID, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	st := f.account(a)
	u := st.users[name]
	if u == nil {
		return notFound("user", name)
	}
	if len(u.keys) > 0 || len(u.attached) > 0 || len(u.inline) > 0 || len(u.groups) > 0 || u.login != nil ||
		st.mfaAssigned(name) {
		return conflict("Cannot delete entity, must delete login profile, access keys, policies and group memberships first.")
	}
	delete(st.users, name)
	return nil
}

// UpdateUser implements Admin. A rename moves the user and its group
// memberships; the id stays the same. Live access keys and console sessions
// keep working under the new ARN. A non-empty expectARN must match the
// current ARN, so a change between the caller's authorization and this call
// is a conflict rather than a move of another user or path.
func (f *Fake) UpdateUser(_ context.Context, a resource.AccountID, name, newPath, newName, expectARN string) error {
	if err := checkName(entityName, "userName", name); err != nil {
		return err
	}
	path := ""
	if newPath != "" {
		p, err := normPathAs(newPath, "newPath")
		if err != nil {
			return err
		}
		path = p
	}
	if newName != "" {
		if err := checkName(entityName, "newUserName", newName); err != nil {
			return err
		}
		if strings.EqualFold(newName, RootUserName) {
			return resource.Invalid("newUserName", "the user name "+RootUserName+" is reserved for the account root")
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	st := f.account(a)
	u := st.users[name]
	if u == nil {
		return notFound("user", name)
	}
	if expectARN != "" && u.ARN != expectARN {
		return conflict("The user changed while the request was in flight.")
	}
	target := name
	if newName != "" {
		target = newName
	}
	if target != name {
		for existing := range st.users {
			if existing != name && strings.EqualFold(existing, target) {
				return exists("User", target)
			}
		}
	}
	if path == "" {
		path = u.Path
	}
	if target == name && path == u.Path {
		return nil
	}
	oldARN := u.ARN
	if target != name {
		delete(st.users, name)
		for group := range u.groups {
			g := st.groups[group]
			if g == nil {
				delete(u.groups, group)
				continue
			}
			delete(g.members, name)
			g.members[target] = true
		}
		st.users[target] = u
		for _, d := range st.mfa {
			if d.user == name {
				d.user = target
			}
		}
	}
	u.Name, u.Path, u.ARN = target, path, iamARN(a, "user", path, target)
	for id, key := range f.keys {
		if key.Principal.ARN == oldARN {
			key.Principal.ARN = u.ARN
			f.keys[id] = key
		}
	}
	f.sessions.rename(a, oldARN, u.ARN)
	return nil
}

// --- access keys ---

// CreateAccessKey implements Admin. The secret is returned only here.
func (f *Fake) CreateAccessKey(_ context.Context, a resource.AccountID, user string) (NewAccessKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u := f.account(a).users[user]
	if u == nil {
		return NewAccessKey{}, notFound("user", user)
	}
	if len(u.keys) >= maxAccessKeysPerUser {
		return NewAccessKey{}, quota("Cannot exceed quota for AccessKeysPerUser: 2")
	}
	k := NewAccessKey{AccessKeyMeta: AccessKeyMeta{UserName: user, AccessKeyID: randID("AKIA", 16), Status: "Active", Created: f.now()}, Secret: randSecret(30)}
	u.keys[k.AccessKeyID] = true
	f.keys[k.AccessKeyID] = Key{AccessKey: k.AccessKeyID, Secret: k.Secret, Principal: Principal{Account: a, ARN: u.ARN}}
	return k, nil
}

// ListAccessKeys implements Admin.
func (f *Fake) ListAccessKeys(_ context.Context, a resource.AccountID, user string) ([]AccessKeyMeta, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	u := f.account(a).users[user]
	if u == nil {
		return nil, notFound("user", user)
	}
	out := []AccessKeyMeta{}
	for id := range u.keys {
		out = append(out, AccessKeyMeta{UserName: user, AccessKeyID: id, Status: "Active", Created: u.Created})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AccessKeyID < out[j].AccessKeyID })
	return out, nil
}

// GetAccessKeyLastUsed implements Admin. The AWS request names only the key,
// so the owning user comes from the account's keys.
func (f *Fake) GetAccessKeyLastUsed(_ context.Context, a resource.AccountID, keyID string) (AccessKeyLastUsed, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if st := f.accounts[a]; st != nil {
		for name, u := range st.users {
			if !u.keys[keyID] {
				continue
			}
			out := AccessKeyLastUsed{UserName: name, UserARN: u.ARN}
			if used, ok := f.used[keyID]; ok {
				out.LastUsed, out.Service, out.Region = used.at, used.service, used.region
			}
			return out, nil
		}
	}
	return AccessKeyLastUsed{}, AccessKeyNotFound(keyID)
}

// DeleteAccessKey implements Admin. The key stops authenticating at once.
func (f *Fake) DeleteAccessKey(_ context.Context, a resource.AccountID, user, keyID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	u := f.account(a).users[user]
	if u == nil {
		return notFound("user", user)
	}
	if !u.keys[keyID] {
		return notFound("Access Key", keyID)
	}
	delete(u.keys, keyID)
	delete(f.keys, keyID)
	delete(f.used, keyID)
	return nil
}

// --- groups ---

// CreateGroup implements Admin.
func (f *Fake) CreateGroup(_ context.Context, a resource.AccountID, name, path string) (Group, error) {
	if err := checkName(groupName, "groupName", name); err != nil {
		return Group{}, err
	}
	path, err := normPath(path)
	if err != nil {
		return Group{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	st := f.account(a)
	if st.groups[name] != nil {
		return Group{}, exists("Group", name)
	}
	g := Group{Name: name, Path: path, ID: randID("AGPA", 17), ARN: iamARN(a, "group", path, name), Created: f.now()}
	st.groups[name] = &groupRec{Group: g, holder: newHolder(), members: map[string]bool{}}
	return g, nil
}

// GetGroup implements Admin and returns the members.
func (f *Fake) GetGroup(_ context.Context, a resource.AccountID, name string) (Group, []User, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	st := f.account(a)
	g := st.groups[name]
	if g == nil {
		return Group{}, nil, notFound("group", name)
	}
	users := []User{}
	for m := range g.members {
		users = append(users, st.users[m].User)
	}
	sort.Slice(users, func(i, j int) bool { return users[i].Name < users[j].Name })
	return g.Group, users, nil
}

// ListGroups implements Admin.
func (f *Fake) ListGroups(_ context.Context, a resource.AccountID, prefix string) ([]Group, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := []Group{}
	for _, g := range f.account(a).groups {
		if strings.HasPrefix(g.Path, prefixOr(prefix)) {
			out = append(out, g.Group)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// UpdateGroup implements Admin. A rename moves the group and its memberships;
// the id stays the same.
func (f *Fake) UpdateGroup(_ context.Context, a resource.AccountID, name, newPath, newName string) error {
	if err := checkName(groupName, "groupName", name); err != nil {
		return err
	}
	path := ""
	if newPath != "" {
		p, err := normPathAs(newPath, "newPath")
		if err != nil {
			return err
		}
		path = p
	}
	if newName != "" {
		if err := checkName(groupName, "newGroupName", newName); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	st := f.account(a)
	g := st.groups[name]
	if g == nil {
		return notFound("group", name)
	}
	target := name
	if newName != "" {
		target = newName
	}
	if target != name && st.groups[target] != nil {
		return exists("Group", target)
	}
	if path == "" {
		path = g.Path
	}
	if target != name {
		delete(st.groups, name)
		for user := range g.members {
			delete(st.users[user].groups, name)
			st.users[user].groups[target] = true
		}
		st.groups[target] = g
	}
	g.Name, g.Path, g.ARN = target, path, iamARN(a, "group", path, target)
	return nil
}

// DeleteGroup implements Admin.
func (f *Fake) DeleteGroup(_ context.Context, a resource.AccountID, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	st := f.account(a)
	g := st.groups[name]
	if g == nil {
		return notFound("group", name)
	}
	if len(g.members) > 0 || len(g.attached) > 0 || len(g.inline) > 0 {
		return conflict("Cannot delete entity, must remove users and policies from group first.")
	}
	delete(st.groups, name)
	return nil
}

// AddUserToGroup implements Admin.
func (f *Fake) AddUserToGroup(_ context.Context, a resource.AccountID, group, user string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	st := f.account(a)
	g, u := st.groups[group], st.users[user]
	if g == nil {
		return notFound("group", group)
	}
	if u == nil {
		return notFound("user", user)
	}
	if !u.groups[group] && len(u.groups) >= maxGroupsPerUser {
		return quota("Cannot exceed quota for GroupsPerUser: 10")
	}
	g.members[user], u.groups[group] = true, true
	return nil
}

// RemoveUserFromGroup implements Admin.
func (f *Fake) RemoveUserFromGroup(_ context.Context, a resource.AccountID, group, user string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	st := f.account(a)
	g, u := st.groups[group], st.users[user]
	if g == nil {
		return notFound("group", group)
	}
	if u == nil || !g.members[user] {
		return notFound("user", user)
	}
	delete(g.members, user)
	delete(u.groups, group)
	return nil
}

// ListGroupsForUser implements Admin.
func (f *Fake) ListGroupsForUser(_ context.Context, a resource.AccountID, user string) ([]Group, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	st := f.account(a)
	u := st.users[user]
	if u == nil {
		return nil, notFound("user", user)
	}
	out := []Group{}
	for g := range u.groups {
		out = append(out, st.groups[g].Group)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// --- roles ---

// CreateRole implements Admin.
func (f *Fake) CreateRole(_ context.Context, a resource.AccountID, in RoleInput) (Role, error) {
	if err := checkName(entityName, "roleName", in.Name); err != nil {
		return Role{}, err
	}
	path, err := normPath(in.Path)
	if err != nil {
		return Role{}, err
	}
	maxSession := in.MaxSessionDuration
	if maxSession == 0 {
		maxSession = defaultMaxSession
	}
	if err := ValidateMaxSessionDuration(maxSession); err != nil {
		return Role{}, err
	}
	trust, err := parsePolicy(in.TrustPolicy, true)
	if err != nil {
		return Role{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	st := f.account(a)
	if st.roles[in.Name] != nil {
		return Role{}, exists("Role", in.Name)
	}
	r := Role{
		Name: in.Name, Path: path, ID: randID("AROA", 17), ARN: iamARN(a, "role", path, in.Name),
		TrustPolicy: in.TrustPolicy, Description: in.Description, MaxSessionDuration: maxSession, Created: f.now(),
	}
	st.roles[in.Name] = &roleRec{Role: r, holder: newHolder(), trust: trust}
	return r, nil
}

// GetRole implements Admin.
func (f *Fake) GetRole(_ context.Context, a resource.AccountID, name string) (Role, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	r := f.account(a).roles[name]
	if r == nil {
		return Role{}, notFound("role", name)
	}
	return r.Role, nil
}

// UpdateRole implements Admin.
func (f *Fake) UpdateRole(_ context.Context, a resource.AccountID, name string, in RoleUpdate) error {
	if in.Description != nil {
		if err := ValidateRoleDescription(*in.Description); err != nil {
			return err
		}
	}
	if in.MaxSessionDuration != nil {
		if err := ValidateMaxSessionDuration(*in.MaxSessionDuration); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.account(a).roles[name]
	if r == nil {
		return notFound("role", name)
	}
	if IsServiceLinkedRole(r.Path) {
		return UnmodifiableRole(name)
	}
	if in.Description != nil {
		r.Description = *in.Description
	}
	if in.MaxSessionDuration != nil {
		r.MaxSessionDuration = *in.MaxSessionDuration
	}
	return nil
}

// UpdateRoleDescription implements Admin.
func (f *Fake) UpdateRoleDescription(_ context.Context, a resource.AccountID, name, description string) (Role, error) {
	if err := ValidateRoleDescription(description); err != nil {
		return Role{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.account(a).roles[name]
	if r == nil {
		return Role{}, notFound("role", name)
	}
	if IsServiceLinkedRole(r.Path) {
		return Role{}, UnmodifiableRole(name)
	}
	r.Description = description
	return r.Role, nil
}

// ListRoles implements Admin.
func (f *Fake) ListRoles(_ context.Context, a resource.AccountID, prefix string) ([]Role, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := []Role{}
	for _, r := range f.account(a).roles {
		if strings.HasPrefix(r.Path, prefixOr(prefix)) {
			out = append(out, r.Role)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// UpdateAssumeRolePolicy implements Admin.
func (f *Fake) UpdateAssumeRolePolicy(_ context.Context, a resource.AccountID, name, document string) error {
	trust, err := parsePolicy(document, true)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.account(a).roles[name]
	if r == nil {
		return notFound("role", name)
	}
	r.TrustPolicy = document
	r.trust = trust
	return nil
}

// DeleteRole implements Admin.
func (f *Fake) DeleteRole(_ context.Context, a resource.AccountID, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	st := f.account(a)
	r := st.roles[name]
	if r == nil {
		return notFound("role", name)
	}
	if len(r.attached) > 0 || len(r.inline) > 0 {
		return conflict("Cannot delete entity, must detach all policies first.")
	}
	delete(st.roles, name)
	return nil
}

// --- managed policies ---

// CreatePolicy implements Admin.
func (f *Fake) CreatePolicy(_ context.Context, a resource.AccountID, name, path, document, description string) (ManagedPolicy, error) {
	if err := checkName(policyName, "policyName", name); err != nil {
		return ManagedPolicy{}, err
	}
	path, err := normPath(path)
	if err != nil {
		return ManagedPolicy{}, err
	}
	parsed, err := parsePolicy(document, false)
	if err != nil {
		return ManagedPolicy{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	st := f.account(a)
	arn := iamARN(a, "policy", path, name)
	for _, p := range st.policies {
		if p.Name == name {
			return ManagedPolicy{}, &resource.Error{Code: resource.CodeAlreadyExists, Message: "A policy called " + name + " already exists. Duplicate names are not allowed."}
		}
	}
	now := f.now()
	p := ManagedPolicy{
		Name: name, Path: path, ID: randID("ANPA", 17), ARN: arn, Description: description,
		DefaultVersion: "v1", Created: now, Updated: now,
	}
	st.policies[arn] = &policyRec{
		ManagedPolicy: p,
		versions: []policyVersionRec{{
			PolicyVersion: PolicyVersion{ID: "v1", Document: document, Created: now},
			parsed:        parsed,
		}},
		nextVersion: 2,
		tags:        map[string]string{},
	}
	return p, nil
}

func (st *store) policy(arn string) (*policyRec, error) {
	p := st.policies[arn]
	if p == nil {
		return nil, &resource.Error{Code: resource.CodeNotFound, Message: "Policy " + arn + " does not exist or is not attachable."}
	}
	return p, nil
}

// GetPolicy implements Admin.
func (f *Fake) GetPolicy(_ context.Context, a resource.AccountID, arn string) (ManagedPolicy, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	p, err := f.account(a).policy(arn)
	if err != nil {
		return ManagedPolicy{}, err
	}
	return p.ManagedPolicy, nil
}

// ListPolicyVersions implements Admin.
func (f *Fake) ListPolicyVersions(
	_ context.Context, a resource.AccountID, arn, marker string, maxItems int,
) (PolicyVersionPage, error) {
	if maxItems <= 0 {
		maxItems = DefaultTagPageSize
	}
	if maxItems > MaxTagPageSize {
		maxItems = MaxTagPageSize
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	p, err := f.account(a).policy(arn)
	if err != nil {
		return PolicyVersionPage{}, err
	}
	versions := make([]PolicyVersion, len(p.versions))
	for i, v := range p.versions {
		v.IsDefaultVersion = v.ID == p.DefaultVersion
		v.Document = "" // AWS ListPolicyVersions leaves out the document.
		versions[i] = v.PolicyVersion
	}
	start := 0
	if marker != "" {
		start = sort.Search(len(versions), func(i int) bool { return versions[i].ID > marker })
	}
	end := min(start+maxItems, len(versions))
	page := PolicyVersionPage{Versions: versions[start:end]}
	if end < len(versions) {
		page.IsTruncated = true
		page.Marker = versions[end-1].ID
	}
	return page, nil
}

// CreatePolicyVersion implements Admin. It stores the document as the next
// version id, as vws-iam does.
func (f *Fake) CreatePolicyVersion(
	_ context.Context, a resource.AccountID, arn, document string, setAsDefault bool,
) (PolicyVersion, error) {
	parsed, err := parsePolicy(document, false)
	if err != nil {
		return PolicyVersion{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	p, err := f.account(a).policy(arn)
	if err != nil {
		return PolicyVersion{}, err
	}
	if len(p.versions) >= maxPolicyVersions {
		return PolicyVersion{}, quota("Cannot exceed quota for PolicyVersions: 5")
	}
	next := p.nextVersion
	if next == 0 {
		next = len(p.versions) + 1
	}
	now := f.now()
	v := PolicyVersion{ID: "v" + strconv.Itoa(next), Document: document, Created: now}
	p.versions = append(p.versions, policyVersionRec{PolicyVersion: v, parsed: parsed})
	p.nextVersion = next + 1
	if setAsDefault {
		p.DefaultVersion = v.ID
		v.IsDefaultVersion = true
	}
	p.Updated = now
	return v, nil
}

// GetPolicyVersion implements Admin.
func (f *Fake) GetPolicyVersion(
	_ context.Context, a resource.AccountID, arn, versionID string,
) (PolicyVersion, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	p, err := f.account(a).policy(arn)
	if err != nil {
		return PolicyVersion{}, err
	}
	for _, v := range p.versions {
		if v.ID == versionID {
			v.IsDefaultVersion = v.ID == p.DefaultVersion
			return v.PolicyVersion, nil
		}
	}
	return PolicyVersion{}, &resource.Error{
		Code:    resource.CodeNotFound,
		Message: "Policy " + arn + " version " + versionID + " does not exist or is not attachable.",
	}
}

// ListPolicies implements Admin (customer managed policies only).
func (f *Fake) ListPolicies(_ context.Context, a resource.AccountID, prefix string) ([]ManagedPolicy, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := []ManagedPolicy{}
	for _, p := range f.account(a).policies {
		if strings.HasPrefix(p.Path, prefixOr(prefix)) {
			out = append(out, p.ManagedPolicy)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// DeletePolicy implements Admin.
func (f *Fake) DeletePolicy(_ context.Context, a resource.AccountID, arn string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	st := f.account(a)
	p, err := st.policy(arn)
	if err != nil {
		return err
	}
	if p.AttachmentCount > 0 {
		return conflict("Cannot delete a policy attached to entities.")
	}
	if len(p.versions) > 1 {
		return conflict("Cannot delete a policy with non-default versions.")
	}
	delete(st.policies, arn)
	return nil
}

// SetDefaultPolicyVersion implements Admin.
func (f *Fake) SetDefaultPolicyVersion(_ context.Context, a resource.AccountID, arn, version string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, err := f.account(a).policy(arn)
	if err != nil {
		return err
	}
	for i := range p.versions {
		if p.versions[i].ID != version {
			continue
		}
		p.DefaultVersion = version
		p.Updated = f.now()
		return nil
	}
	return &resource.Error{
		Code:    resource.CodeNotFound,
		Message: "Policy version " + version + " does not exist or is not attachable.",
	}
}

// DeletePolicyVersion implements Admin. The default version cannot be
// deleted; any other version is removed from the policy.
func (f *Fake) DeletePolicyVersion(_ context.Context, a resource.AccountID, arn, versionID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, err := f.account(a).policy(arn)
	if err != nil {
		return err
	}
	for i := range p.versions {
		if p.versions[i].ID != versionID {
			continue
		}
		if versionID == p.DefaultVersion {
			return conflict("the default version cannot be deleted")
		}
		p.versions = append(p.versions[:i], p.versions[i+1:]...)
		p.Updated = f.now()
		return nil
	}
	return &resource.Error{
		Code:    resource.CodeNotFound,
		Message: "Policy " + p.ARN + " version " + versionID + " does not exist or is not attachable.",
	}
}

// --- policy tags ---

// TagPolicy implements Admin. A named key is overwritten; the whole request
// fails and stores nothing when a tag is invalid or the policy would keep
// more than 50 tags.
func (f *Fake) TagPolicy(_ context.Context, a resource.AccountID, arn string, tags []Tag) error {
	if len(tags) < 1 || len(tags) > MaxTags {
		return validationError("tags", "Member must have length between 1 and 50")
	}
	if err := ValidateTags(tags); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	p, err := f.account(a).policy(arn)
	if err != nil {
		return err
	}
	merged := make(map[string]string, len(p.tags)+len(tags))
	for k, v := range p.tags {
		merged[k] = v
	}
	for _, tag := range tags {
		merged[tag.Key] = tag.Value
	}
	if len(merged) > MaxTags {
		return quota("Cannot exceed quota for TagsPerPolicy: 50")
	}
	p.tags = merged
	return nil
}

// UntagPolicy implements Admin. A key that is not attached is ignored.
func (f *Fake) UntagPolicy(_ context.Context, a resource.AccountID, arn string, keys []string) error {
	if len(keys) < 1 || len(keys) > MaxTags {
		return validationError("tagKeys", "Member must have length between 1 and 50")
	}
	for _, key := range keys {
		if err := ValidateTagKey(key); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	p, err := f.account(a).policy(arn)
	if err != nil {
		return err
	}
	for _, key := range keys {
		delete(p.tags, key)
	}
	return nil
}

// ListPolicyTags implements Admin. Tags are sorted by key and paged with an
// opaque marker, as in AWS.
func (f *Fake) ListPolicyTags(
	_ context.Context, a resource.AccountID, arn, marker string, maxItems int,
) (TagPage, error) {
	if maxItems <= 0 {
		maxItems = DefaultTagPageSize
	}
	if maxItems > MaxTagPageSize {
		maxItems = MaxTagPageSize
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	p, err := f.account(a).policy(arn)
	if err != nil {
		return TagPage{}, err
	}
	keys := make([]string, 0, len(p.tags))
	for key := range p.tags {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	start := 0
	if marker != "" {
		start = sort.Search(len(keys), func(i int) bool { return keys[i] > marker })
	}
	end := min(start+maxItems, len(keys))
	page := TagPage{Tags: []Tag{}}
	for _, key := range keys[start:end] {
		page.Tags = append(page.Tags, Tag{Key: key, Value: p.tags[key]})
	}
	if end < len(keys) {
		page.IsTruncated = true
		page.Marker = keys[end-1]
	}
	return page, nil
}

// mfaAssigned reports whether an MFA device is enabled for user. The caller
// holds f.mu.
func (st *store) mfaAssigned(user string) bool {
	for _, d := range st.mfa {
		if d.user == user {
			return true
		}
	}
	return false
}

// ListVirtualMFADevices implements Admin. Devices are sorted by serial number
// and paged with an opaque marker, as in AWS.
func (f *Fake) ListVirtualMFADevices(
	_ context.Context, a resource.AccountID, assignment MFADeviceAssignment, marker string, maxItems int,
) (VirtualMFADevicePage, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	st := f.account(a)
	devices := make([]VirtualMFADevice, 0, len(st.mfa))
	for serial, d := range st.mfa {
		v := VirtualMFADevice{SerialNumber: serial}
		if d.user != "" {
			u := st.users[d.user]
			if u == nil {
				return VirtualMFADevicePage{}, notFound("user", d.user)
			}
			user := u.User
			v.User = &user
			v.EnableDate = d.enableTime
		}
		devices = append(devices, v)
	}
	return PageVirtualMFADevices(devices, assignment, marker, maxItems), nil
}

// ListMFADevices implements Admin. Only devices enabled for the named user are
// listed; a missing user is NotFound.
func (f *Fake) ListMFADevices(
	_ context.Context, a resource.AccountID, user, marker string, maxItems int,
) (MFADevicePage, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	st := f.account(a)
	if st.users[user] == nil {
		return MFADevicePage{}, notFound("user", user)
	}
	devices := make([]MFADevice, 0, len(st.mfa))
	for serial, d := range st.mfa {
		if d.user != user {
			continue
		}
		devices = append(devices, MFADevice{
			UserName: user, SerialNumber: serial, EnableDate: d.enableTime,
		})
	}
	return PageMFADevices(devices, marker, maxItems), nil
}

// --- virtual MFA device tags ---

func mfaDeviceNotFound() error {
	return &resource.Error{Code: resource.CodeNotFound, Message: "The specified MFA device does not exist."}
}

// mfaDevice returns the device with serial. The caller holds f.mu.
func (st *store) mfaDevice(serial string) (*mfaDeviceRec, error) {
	d := st.mfa[serial]
	if d == nil {
		return nil, mfaDeviceNotFound()
	}
	return d, nil
}

// TagMFADevice implements Admin. A named key is overwritten; the whole request
// fails and stores nothing when a tag is invalid or the device would keep more
// than 50 tags.
func (f *Fake) TagMFADevice(_ context.Context, a resource.AccountID, serial string, tags []Tag) error {
	if len(tags) < 1 || len(tags) > MaxTags {
		return validationError("tags", "Member must have length between 1 and 50")
	}
	if err := ValidateTags(tags); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	d, err := f.account(a).mfaDevice(serial)
	if err != nil {
		return err
	}
	merged := make(map[string]string, len(d.tags)+len(tags))
	for k, v := range d.tags {
		merged[k] = v
	}
	for _, tag := range tags {
		merged[tag.Key] = tag.Value
	}
	if len(merged) > MaxTags {
		return quota("Cannot exceed quota for TagsPerMfaDevice: 50")
	}
	d.tags = merged
	return nil
}

// UntagMFADevice implements Admin. A key that is not attached is ignored.
func (f *Fake) UntagMFADevice(_ context.Context, a resource.AccountID, serial string, keys []string) error {
	if len(keys) < 1 || len(keys) > MaxTags {
		return validationError("tagKeys", "Member must have length between 1 and 50")
	}
	for _, key := range keys {
		if err := ValidateTagKey(key); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	d, err := f.account(a).mfaDevice(serial)
	if err != nil {
		return err
	}
	for _, key := range keys {
		delete(d.tags, key)
	}
	return nil
}

// ListMFADeviceTags implements Admin. Tags are sorted by key and paged with an
// opaque marker, as in AWS.
func (f *Fake) ListMFADeviceTags(
	_ context.Context, a resource.AccountID, serial, marker string, maxItems int,
) (TagPage, error) {
	if maxItems <= 0 {
		maxItems = DefaultTagPageSize
	}
	if maxItems > MaxTagPageSize {
		maxItems = MaxTagPageSize
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	d, err := f.account(a).mfaDevice(serial)
	if err != nil {
		return TagPage{}, err
	}
	keys := make([]string, 0, len(d.tags))
	for key := range d.tags {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	start := 0
	if marker != "" {
		start = sort.Search(len(keys), func(i int) bool { return keys[i] > marker })
	}
	end := min(start+maxItems, len(keys))
	page := TagPage{Tags: []Tag{}}
	for _, key := range keys[start:end] {
		page.Tags = append(page.Tags, Tag{Key: key, Value: d.tags[key]})
	}
	if end < len(keys) {
		page.IsTruncated = true
		page.Marker = keys[end-1]
	}
	return page, nil
}

func (st *store) holderOf(kind Entity, name string) (*holder, error) {
	switch kind {
	case EntityUser:
		if u := st.users[name]; u != nil {
			return &u.holder, nil
		}
	case EntityGroup:
		if g := st.groups[name]; g != nil {
			return &g.holder, nil
		}
	case EntityRole:
		if r := st.roles[name]; r != nil {
			return &r.holder, nil
		}
	}
	return nil, notFound(kind.String(), name)
}

// AttachPolicy implements Admin.
func (f *Fake) AttachPolicy(_ context.Context, a resource.AccountID, kind Entity, name, arn string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	st := f.account(a)
	h, err := st.holderOf(kind, name)
	if err != nil {
		return err
	}
	p, err := st.policy(arn)
	if err != nil {
		return err
	}
	if h.attached[arn] {
		return nil
	}
	if len(h.attached) >= maxAttachedPerEntity {
		return quota("Cannot exceed quota for PoliciesPerEntity: 10")
	}
	h.attached[arn] = true
	p.AttachmentCount++
	return nil
}

// DetachPolicy implements Admin.
func (f *Fake) DetachPolicy(_ context.Context, a resource.AccountID, kind Entity, name, arn string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	st := f.account(a)
	h, err := st.holderOf(kind, name)
	if err != nil {
		return err
	}
	p, err := st.policy(arn)
	if err != nil {
		return err
	}
	if !h.attached[arn] {
		return &resource.Error{Code: resource.CodeNotFound, Message: "Policy " + arn + " was not found."}
	}
	delete(h.attached, arn)
	p.AttachmentCount--
	return nil
}

// ListAttachedPolicies implements Admin.
func (f *Fake) ListAttachedPolicies(_ context.Context, a resource.AccountID, kind Entity, name string) ([]ManagedPolicy, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	st := f.account(a)
	h, err := st.holderOf(kind, name)
	if err != nil {
		return nil, err
	}
	out := []ManagedPolicy{}
	for arn := range h.attached {
		out = append(out, st.policies[arn].ManagedPolicy)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// --- inline policies ---

// PutInlinePolicy implements Admin. It replaces a policy of the same name.
func (f *Fake) PutInlinePolicy(_ context.Context, a resource.AccountID, kind Entity, name, policy, document string) error {
	if err := checkName(policyName, "policyName", policy); err != nil {
		return err
	}
	parsed, err := parsePolicy(document, false)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	h, err := f.account(a).holderOf(kind, name)
	if err != nil {
		return err
	}
	h.inline[policy], h.parsed[policy] = document, parsed
	return nil
}

// GetInlinePolicy implements Admin.
func (f *Fake) GetInlinePolicy(_ context.Context, a resource.AccountID, kind Entity, name, policy string) (string, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	h, err := f.account(a).holderOf(kind, name)
	if err != nil {
		return "", err
	}
	doc, ok := h.inline[policy]
	if !ok {
		return "", notFound("policy", policy)
	}
	return doc, nil
}

// DeleteInlinePolicy implements Admin.
func (f *Fake) DeleteInlinePolicy(_ context.Context, a resource.AccountID, kind Entity, name, policy string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	h, err := f.account(a).holderOf(kind, name)
	if err != nil {
		return err
	}
	if _, ok := h.inline[policy]; !ok {
		return notFound("policy", policy)
	}
	delete(h.inline, policy)
	delete(h.parsed, policy)
	return nil
}

// ListInlinePolicies implements Admin.
func (f *Fake) ListInlinePolicies(_ context.Context, a resource.AccountID, kind Entity, name string) ([]string, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	h, err := f.account(a).holderOf(kind, name)
	if err != nil {
		return nil, err
	}
	out := []string{}
	for p := range h.inline {
		out = append(out, p)
	}
	sort.Strings(out)
	return out, nil
}

// --- STS ---

// AssumeRole implements Admin. The role's trust policy must admit caller;
// whether caller may call sts:AssumeRole at all is the surface's Authorize.
// Role chaining keeps AWS's one-hour cap.
func (f *Fake) AssumeRole(_ context.Context, caller Principal, roleARN, session string, duration time.Duration) (AssumedRole, error) {
	if err := checkName(sessionName, "roleSessionName", session); err != nil {
		return AssumedRole{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	st := f.account(caller.Account)
	var role *roleRec
	for _, r := range st.roles {
		if r.ARN == roleARN {
			role = r
		}
	}
	if role == nil {
		return AssumedRole{}, &resource.Error{Code: resource.CodeNotFound, Message: "Role " + roleARN + " cannot be found."}
	}
	limit := time.Duration(role.MaxSessionDuration) * time.Second
	if _, chained := assumedRoleName(caller.ARN); chained {
		limit = time.Hour
	}
	if duration == 0 {
		duration = time.Hour
	}
	if duration < minSession || duration > limit {
		return AssumedRole{}, resource.Invalid("durationSeconds", "The requested DurationSeconds exceeds the MaxSessionDuration set for this role.")
	}
	if !trustAdmits(role.trust, caller) {
		return AssumedRole{}, resource.Denied("User: " + caller.ARN + " is not authorized to perform: sts:AssumeRole on resource: " + roleARN)
	}
	arn := "arn:vws:sts::" + caller.Account.String() + ":assumed-role/" + role.Name + "/" + session
	k := Key{
		AccessKey: randID("ASIA", 16), Secret: randSecret(30), SessionToken: randSecret(96),
		Expires: f.now().Add(duration), Principal: Principal{Account: caller.Account, ARN: arn},
	}
	f.keys[k.AccessKey] = k
	f.gcSessions()
	return AssumedRole{Key: k, AssumedRoleID: role.ID + ":" + session, ARN: arn}, nil
}

// gcSessions drops expired temporary keys. The caller holds f.mu.
func (f *Fake) gcSessions() {
	now := f.now()
	for id, k := range f.keys {
		if k.SessionToken != "" && !k.Expires.IsZero() && !now.Before(k.Expires) {
			delete(f.keys, id)
			delete(f.used, id)
		}
	}
}
