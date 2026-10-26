package iamquery

import (
	"encoding/xml"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

// policyVersionRE is the AWS VersionId pattern.
var policyVersionRE = regexp.MustCompile(`^v[1-9][0-9]*(\.[A-Za-z0-9-]*)?$`)

// policyARNRE is the AWS managed policy ARN shape. A well-formed ARN for
// another account is left for the backend to report as missing.
var policyARNRE = regexp.MustCompile(`^arn:[^:]+:iam::[0-9]{12}:policy/.+$`)

// accessKeyIDRE is the AWS AccessKeyId shape.
var accessKeyIDRE = regexp.MustCompile(`^\w{16,128}$`)

// accessKeyIDParam reads the required AccessKeyId in the AWS shape.
func accessKeyIDParam(c *exchange) (string, error) {
	if err := required(c, "AccessKeyId"); err != nil {
		return "", err
	}
	id := c.form("AccessKeyId")
	if !accessKeyIDRE.MatchString(id) {
		return "", resource.Invalid("accessKeyId",
			"1 validation error detected: Value '"+id+"' at 'accessKeyId' failed to satisfy constraint: "+
				`Member must satisfy regular expression pattern: [\w]+`)
	}
	return id, nil
}

// spec is one action: the form keys it reads, the ARN it is authorized on
// (nil means "*"), and what it does.
type spec struct {
	params []string
	// prefixes are form key prefixes the action reads (the indexed members of
	// an AWS list, such as Tags.member.1.Key). The action validates them.
	prefixes   []string
	list       bool // also accepts Marker, MaxItems and PathPrefix
	needsAdmin bool
	// public skips Authorize, as AWS does for sts:GetCallerIdentity. The
	// signature is still verified.
	public   bool
	resource func(h *handler, c *exchange) string
	run      func(h *handler, c *exchange) (any, error)
}

func (s spec) allows(k string) bool {
	if s.list && (k == "Marker" || k == "MaxItems" || k == "PathPrefix") {
		return true
	}
	for _, p := range s.params {
		if p == k {
			return true
		}
	}
	for _, p := range s.prefixes {
		if strings.HasPrefix(k, p) {
			return true
		}
	}
	return false
}

func admin(params []string, res func(h *handler, c *exchange) string, run func(h *handler, c *exchange) (any, error)) spec {
	return spec{params: params, needsAdmin: true, resource: res, run: run}
}

func lister(params []string, run func(h *handler, c *exchange) (any, error)) spec {
	return spec{params: params, list: true, needsAdmin: true, run: run}
}

func actionTable() map[sigv4.Service]map[string]spec {
	return map[sigv4.Service]map[string]spec{sigv4.ServiceIAM: iamActions(), sigv4.ServiceSTS: stsActions()}
}

func arnOf(c *exchange, kind, path, name string) string {
	return "arn:vws:iam::" + c.caller.Account.String() + ":" + kind + path + name
}

// userName is UserName, or the calling user when it is omitted, as in AWS.
func userName(c *exchange) string {
	if n := c.form("UserName"); n != "" {
		return n
	}
	prefix := "arn:vws:iam::" + c.caller.Account.String() + ":user/"
	if rest, ok := strings.CutPrefix(c.caller.Principal, prefix); ok {
		return rest[strings.LastIndex(rest, "/")+1:]
	}
	return ""
}

// userARN is the user's real ARN when it exists, so policies on paths apply.
// Without UserName the call is about the caller, authorized on its own
// authenticated ARN (path included) with no lookup, as AWS does. A named user
// that does not exist is authorized on the name the caller gave, as AWS
// evaluates it. Any other lookup failure fails closed: a guessed path-less
// ARN would skip a Deny on the user's real path.
func userARN(h *handler, c *exchange) string {
	name := c.form("UserName")
	if name == "" {
		return c.caller.Principal
	}
	if c.action == "CreateUser" {
		return arnOf(c, "user", pathOr(c.form("Path")), name)
	}
	u, err := h.cfg.Admin.ResolveUser(c.r.Context(), c.caller.Account, name)
	if err == nil {
		return u.ARN
	}
	if resource.CodeOf(err) != resource.CodeNotFound {
		c.resourceErr = lookupError(err)
	}
	return arnOf(c, "user", "/", name)
}

// lookupError is a failed user or group lookup that is not NoSuchEntity. An
// IAM error is answered as it is; anything else (vws-iam down or timing out)
// answers ServiceUnavailable, as iam.Check does for authorization, and never
// echoes the backend's message. The cause stays in the chain for the log.
func lookupError(err error) error {
	var re *resource.Error
	if errors.As(err, &re) {
		return err
	}
	unavailable := &resource.Error{Code: resource.CodeUnavailable, Message: "identity lookup unavailable"}
	return fmt.Errorf("%w: %w", unavailable, err)
}

// groupARN is the group's real ARN when it exists. As in userARN, a missing
// group is authorized on the requested name, and any other lookup failure
// fails closed.
func groupARN(h *handler, c *exchange) string {
	name := c.form("GroupName")
	if c.action == "CreateGroup" {
		return arnOf(c, "group", pathOr(c.form("Path")), name)
	}
	g, err := h.cfg.Admin.ResolveGroup(c.r.Context(), c.caller.Account, name)
	if err == nil {
		return g.ARN
	}
	if resource.CodeOf(err) != resource.CodeNotFound {
		c.resourceErr = lookupError(err)
	}
	return arnOf(c, "group", "/", name)
}

// authorizeMovedGroup checks iam:UpdateGroup on the group's new ARN too, as
// AWS does when a request changes its name or path. A missing group is left
// for UpdateGroup to report. A group that moved since the action was
// authorized is a ConcurrentModification: its target would be computed from
// a path the caller was never authorized on.
func authorizeMovedGroup(h *handler, c *exchange) error {
	newPath, newName := c.form("NewPath"), c.form("NewGroupName")
	if newPath == "" && newName == "" {
		return nil
	}
	g, _, err := h.cfg.Admin.GetGroup(c.r.Context(), c.caller.Account, c.form("GroupName"), c.authorized)
	if err != nil {
		if resource.CodeOf(err) == resource.CodeNotFound {
			return nil
		}
		return err
	}
	path, name := g.Path, g.Name
	if newPath != "" {
		path = newPath
	}
	if newName != "" {
		name = newName
	}
	target := arnOf(c, "group", path, name)
	if target == g.ARN {
		return nil
	}
	return iam.Check(c.r.Context(), h.cfg.Authorizer, c.caller, "iam:"+c.action, target)
}

// authorizeMovedUser checks iam:UpdateUser on the user's current and target
// ARN, as AWS requires. It returns the binding of the snapshot both checks
// used, so UpdateUser can refuse a concurrent change. A missing user is
// NoSuchEntity, never an empty snapshot.
func authorizeMovedUser(h *handler, c *exchange) (iam.AuthorizedPrincipal, error) {
	ref, err := h.cfg.Admin.ResolveUser(c.r.Context(), c.caller.Account, c.form("UserName"))
	if err != nil {
		return iam.AuthorizedPrincipal{}, err
	}
	want, err := iam.Authorize(c.r.Context(), h.cfg.Authorizer, c.caller, "iam:"+c.action, ref.ARN)
	if err != nil {
		return iam.AuthorizedPrincipal{}, err
	}
	newPath, newName := c.form("NewPath"), c.form("NewUserName")
	if newPath == "" && newName == "" {
		return want, nil
	}
	u, err := h.cfg.Admin.GetUser(c.r.Context(), c.caller.Account, c.form("UserName"), want)
	if err != nil {
		return iam.AuthorizedPrincipal{}, err
	}
	path, name := u.Path, u.Name
	if newPath != "" {
		path = newPath
	}
	if newName != "" {
		name = newName
	}
	target := arnOf(c, "user", path, name)
	if target == u.ARN {
		return want, nil
	}
	if err := iam.Check(c.r.Context(), h.cfg.Authorizer, c.caller, "iam:"+c.action, target); err != nil {
		return iam.AuthorizedPrincipal{}, err
	}
	return want, nil
}

func roleARN(h *handler, c *exchange) string {
	name := c.form("RoleName")
	if c.action == "CreateRole" {
		return arnOf(c, "role", pathOr(c.form("Path")), name)
	}
	r, err := h.cfg.Admin.ResolveRole(c.r.Context(), c.caller.Account, name)
	if err == nil {
		return r.ARN
	}
	if resource.CodeOf(err) != resource.CodeNotFound {
		c.resourceErr = err
	}
	return arnOf(c, "role", "/", name)
}

func policyARN(_ *handler, c *exchange) string {
	if c.action == "CreatePolicy" {
		return arnOf(c, "policy", pathOr(c.form("Path")), c.form("PolicyName"))
	}
	return c.form("PolicyArn")
}

func pathOr(p string) string {
	if p == "" {
		return "/"
	}
	return p
}

// readAccessKeyLastUsed reads the key once. A missing key is cached too, so
// the action reports it after authorization instead of failing closed on a
// guessed ARN.
func readAccessKeyLastUsed(h *handler, c *exchange) (iam.AccessKeyLastUsed, error) {
	if c.lastUsedRead {
		return c.lastUsed, c.lastUsedErr
	}
	c.lastUsedRead = true
	if err := required(c, "AccessKeyId"); err != nil {
		c.lastUsedErr = err
		return iam.AccessKeyLastUsed{}, err
	}
	if _, err := accessKeyIDParam(c); err != nil {
		c.lastUsedErr = err
		return iam.AccessKeyLastUsed{}, err
	}
	c.lastUsed, c.lastUsedErr = h.cfg.Admin.GetAccessKeyLastUsed(
		c.r.Context(), c.caller.Account, c.form("AccessKeyId"))
	return c.lastUsed, c.lastUsedErr
}

// accessKeyLastUsedARN authorizes on the owning user's real ARN. A key that
// does not exist is authorized on "*" and reported by the action.
func accessKeyLastUsedARN(h *handler, c *exchange) string {
	got, err := readAccessKeyLastUsed(h, c)
	if err == nil {
		if got.UserARN == "" {
			c.resourceErr = resource.Internal(errors.New("access key owner has no ARN"))
			return "*"
		}
		return got.UserARN
	}
	if code := resource.CodeOf(err); code != resource.CodeNotFound && code != resource.CodeInvalidArgument {
		c.resourceErr = err
	}
	return "*"
}

func required(c *exchange, keys ...string) error {
	for _, k := range keys {
		if c.form(k) == "" {
			return resource.Invalid(lowerFirst(k), "1 validation error detected: Value null at '"+lowerFirst(k)+"' failed to satisfy constraint: Member must not be null")
		}
	}
	return nil
}

func rejectEmpty(c *exchange, keys ...string) error {
	for _, k := range keys {
		if c.r.Form.Has(k) && c.form(k) == "" {
			field := lowerFirst(k)
			msg := "1 validation error detected: Value '' at '" + field +
				"' failed to satisfy constraint: Member must have length greater than or equal to 1"
			return resource.Invalid(field, msg)
		}
	}
	return nil
}

func lowerFirst(s string) string { return strings.ToLower(s[:1]) + s[1:] }

func requireUser(c *exchange) (string, error) {
	n := userName(c)
	if n == "" {
		return "", resource.Invalid("UserName", "Must specify userName when calling with non-User credentials")
	}
	return n, nil
}

type usersResult struct {
	Users       []userXML `xml:"Users>member"`
	IsTruncated bool      `xml:"IsTruncated"`
	Marker      string    `xml:"Marker,omitempty"`
}

type groupsResult struct {
	Groups      []groupXML `xml:"Groups>member"`
	IsTruncated bool       `xml:"IsTruncated"`
	Marker      string     `xml:"Marker,omitempty"`
}

func userNameOf(u iam.User) string   { return u.Name }
func groupNameOf(g iam.Group) string { return g.Name }

// pagedUsers is one Marker/MaxItems page of us.
func pagedUsers(c *exchange, list func(prefix string) ([]iam.User, error)) (any, error) {
	prefix, err := pathPrefixParam(c)
	if err != nil {
		return nil, err
	}
	marker, maxItems, err := pageParams(c)
	if err != nil {
		return nil, err
	}
	us, err := list(prefix)
	if err != nil {
		return nil, err
	}
	page, truncated, next := pageByName(us, userNameOf, marker, maxItems)
	out := usersResult{Users: []userXML{}, IsTruncated: truncated, Marker: next}
	for _, u := range page {
		out.Users = append(out.Users, toUser(u))
	}
	return out, nil
}

// pagedGroups is one Marker/MaxItems page of gs.
func pagedGroups(c *exchange, gs []iam.Group) (any, error) {
	marker, maxItems, err := pageParams(c)
	if err != nil {
		return nil, err
	}
	page, truncated, next := pageByName(gs, groupNameOf, marker, maxItems)
	out := groupsResult{Groups: []groupXML{}, IsTruncated: truncated, Marker: next}
	for _, g := range page {
		out.Groups = append(out.Groups, toGroup(g))
	}
	return out, nil
}

type rolesResult struct {
	Roles       []roleXML `xml:"Roles>member"`
	IsTruncated bool      `xml:"IsTruncated"`
}

type policiesResult struct {
	Policies    []policyXML `xml:"Policies>member"`
	IsTruncated bool        `xml:"IsTruncated"`
}

type attachedResult struct {
	AttachedPolicies []attachedXML `xml:"AttachedPolicies>member"`
	IsTruncated      bool          `xml:"IsTruncated"`
	Marker           string        `xml:"Marker,omitempty"`
}

type namesResult struct {
	PolicyNames []string `xml:"PolicyNames>member"`
	IsTruncated bool     `xml:"IsTruncated"`
	Marker      string   `xml:"Marker,omitempty"`
}

func iamActions() map[string]spec {
	m := map[string]spec{
		"CreateUser": admin([]string{"UserName", "Path"}, userARN, func(h *handler, c *exchange) (any, error) {
			if err := required(c, "UserName"); err != nil {
				return nil, err
			}
			u, err := h.cfg.Admin.CreateUser(c.r.Context(), c.caller.Account, c.form("UserName"), c.form("Path"))
			return struct {
				User userXML `xml:"User"`
			}{toUser(u)}, err
		}),
		"GetUser": admin([]string{"UserName"}, userARN, func(h *handler, c *exchange) (any, error) {
			name := userName(c)
			if name == "" { // the root user asking about itself
				return struct {
					User userXML `xml:"User"`
				}{userXML{UserID: c.caller.Account.String(), Arn: c.caller.Principal}}, nil
			}
			// The lookup is read again for the response; a user that moved
			// since it was authorized is not shown.
			u, err := h.cfg.Admin.GetUser(c.r.Context(), c.caller.Account, name, c.authorized)
			if err != nil {
				return nil, err
			}
			return struct {
				User userXML `xml:"User"`
			}{toUser(u)}, nil
		}),
		"ListUsers": lister(nil, func(h *handler, c *exchange) (any, error) {
			return pagedUsers(c, func(prefix string) ([]iam.User, error) {
				return h.cfg.Admin.ListUsers(c.r.Context(), c.caller.Account, prefix)
			})
		}),
		"UpdateUser": admin(
			[]string{"UserName", "NewPath", "NewUserName"}, userARN,
			func(h *handler, c *exchange) (any, error) {
				if err := required(c, "UserName"); err != nil {
					return nil, err
				}
				if err := rejectEmpty(c, "NewPath", "NewUserName"); err != nil {
					return nil, err
				}
				want, err := authorizeMovedUser(h, c)
				if err != nil {
					return nil, err
				}
				return nil, h.cfg.Admin.UpdateUser(
					c.r.Context(), c.caller.Account, c.form("UserName"),
					c.form("NewPath"), c.form("NewUserName"), want)
			},
		),
		"DeleteUser": admin([]string{"UserName"}, userARN, func(h *handler, c *exchange) (any, error) {
			if err := required(c, "UserName"); err != nil {
				return nil, err
			}
			return nil, h.cfg.Admin.DeleteUser(c.r.Context(), c.caller.Account, c.form("UserName"), c.authorized)
		}),
		"CreateLoginProfile": admin([]string{"UserName", "Password", "PasswordResetRequired"}, userARN, func(h *handler, c *exchange) (any, error) {
			if err := loginProfileInput(c); err != nil {
				return nil, err
			}
			p, err := h.cfg.Admin.CreateLoginProfile(
				c.r.Context(), c.caller.Account, c.form("UserName"), c.form("Password"), c.authorized)
			return struct {
				LoginProfile loginProfileXML `xml:"LoginProfile"`
			}{toLoginProfile(p)}, err
		}),
		"GetLoginProfile": admin([]string{"UserName"}, userARN, func(h *handler, c *exchange) (any, error) {
			if err := required(c, "UserName"); err != nil {
				return nil, err
			}
			p, err := h.cfg.Admin.GetLoginProfile(c.r.Context(), c.caller.Account, c.form("UserName"), c.authorized)
			return struct {
				LoginProfile loginProfileXML `xml:"LoginProfile"`
			}{toLoginProfile(p)}, err
		}),
		"UpdateLoginProfile": admin([]string{"UserName", "Password", "PasswordResetRequired"}, userARN, func(h *handler, c *exchange) (any, error) {
			if err := loginProfileInput(c); err != nil {
				return nil, err
			}
			return nil, h.cfg.Admin.UpdateLoginProfile(
				c.r.Context(), c.caller.Account, c.form("UserName"), c.form("Password"), c.authorized)
		}),
		"DeleteLoginProfile": admin([]string{"UserName"}, userARN, func(h *handler, c *exchange) (any, error) {
			if err := required(c, "UserName"); err != nil {
				return nil, err
			}
			return nil, h.cfg.Admin.DeleteLoginProfile(c.r.Context(), c.caller.Account, c.form("UserName"), c.authorized)
		}),
		"CreateAccessKey": admin([]string{"UserName"}, userARN, func(h *handler, c *exchange) (any, error) {
			n, err := requireUser(c)
			if err != nil {
				return nil, err
			}
			// The backend creates the key only for the user at the authorized
			// ARN. The secret is in this response only.
			k, err := h.cfg.Admin.CreateAccessKey(c.r.Context(), c.caller.Account, n, c.authorized)
			return struct {
				AccessKey accessKeyXML `xml:"AccessKey"`
			}{accessKeyXML{UserName: k.UserName, AccessKeyID: k.AccessKeyID, Status: k.Status, SecretAccessKey: k.Secret, CreateDate: stamp(k.Created)}}, err
		}),
		"ListAccessKeys": {
			params: []string{"UserName", "Marker", "MaxItems"}, needsAdmin: true, resource: userARN,
			run: func(h *handler, c *exchange) (any, error) {
				n, err := requireUser(c)
				if err != nil {
					return nil, err
				}
				marker, maxItems, err := pageParams(c)
				if err != nil {
					return nil, err
				}
				// The backend reads only the user at the authorized ARN, so a
				// user moved since the authorization lists nothing.
				ks, err := h.cfg.Admin.ListAccessKeys(c.r.Context(), c.caller.Account, n, c.authorized)
				if err != nil {
					return nil, err
				}
				page, truncated, next := pageByName(ks, func(k iam.AccessKeyMeta) string { return k.AccessKeyID }, marker, maxItems)
				out := struct {
					Keys        []keyMetaXML `xml:"AccessKeyMetadata>member"`
					UserName    string       `xml:"UserName"`
					IsTruncated bool         `xml:"IsTruncated"`
					Marker      string       `xml:"Marker,omitempty"`
				}{Keys: []keyMetaXML{}, UserName: n, IsTruncated: truncated, Marker: next}
				for _, k := range page {
					out.Keys = append(out.Keys, keyMetaXML{
						UserName: k.UserName, AccessKeyID: k.AccessKeyID, Status: k.Status, CreateDate: stamp(k.Created),
					})
				}
				return out, nil
			},
		},
		"GetAccessKeyLastUsed": {
			params: []string{"AccessKeyId"}, needsAdmin: true,
			resource: accessKeyLastUsedARN,
			run: func(h *handler, c *exchange) (any, error) {
				got, err := readAccessKeyLastUsed(h, c)
				if err != nil {
					return nil, err
				}
				return toAccessKeyLastUsed(got), nil
			},
		},
		"DeleteAccessKey": admin([]string{"UserName", "AccessKeyId"}, userARN, func(h *handler, c *exchange) (any, error) {
			n, err := requireUser(c)
			if err != nil {
				return nil, err
			}
			id, err := accessKeyIDParam(c)
			if err != nil {
				return nil, err
			}
			// The backend deletes only a key of the user at the authorized ARN.
			return nil, h.cfg.Admin.DeleteAccessKey(c.r.Context(), c.caller.Account, n, id, c.authorized)
		}),

		"CreateGroup": admin([]string{"GroupName", "Path"}, groupARN, func(h *handler, c *exchange) (any, error) {
			if err := required(c, "GroupName"); err != nil {
				return nil, err
			}
			g, err := h.cfg.Admin.CreateGroup(c.r.Context(), c.caller.Account, c.form("GroupName"), c.form("Path"))
			return struct {
				Group groupXML `xml:"Group"`
			}{toGroup(g)}, err
		}),
		"GetGroup": {params: []string{"GroupName"}, list: true, needsAdmin: true, resource: groupARN, run: func(h *handler, c *exchange) (any, error) {
			if err := required(c, "GroupName"); err != nil {
				return nil, err
			}
			marker, maxItems, err := pageParams(c)
			if err != nil {
				return nil, err
			}
			// A group that moved since it was authorized is not shown.
			g, us, err := h.cfg.Admin.GetGroup(c.r.Context(), c.caller.Account, c.form("GroupName"), c.authorized)
			if err != nil {
				return nil, err
			}
			page, truncated, next := pageByName(us, userNameOf, marker, maxItems)
			out := struct {
				Group       groupXML  `xml:"Group"`
				Users       []userXML `xml:"Users>member"`
				IsTruncated bool      `xml:"IsTruncated"`
				Marker      string    `xml:"Marker,omitempty"`
			}{Group: toGroup(g), Users: []userXML{}, IsTruncated: truncated, Marker: next}
			for _, u := range page {
				out.Users = append(out.Users, toUser(u))
			}
			return out, nil
		}},
		"ListGroups": lister(nil, func(h *handler, c *exchange) (any, error) {
			prefix, err := pathPrefixParam(c)
			if err != nil {
				return nil, err
			}
			if _, _, err := pageParams(c); err != nil {
				return nil, err
			}
			gs, err := h.cfg.Admin.ListGroups(c.r.Context(), c.caller.Account, prefix)
			if err != nil {
				return nil, err
			}
			return pagedGroups(c, gs)
		}),
		"UpdateGroup": admin(
			[]string{"GroupName", "NewPath", "NewGroupName"}, groupARN,
			func(h *handler, c *exchange) (any, error) {
				if err := required(c, "GroupName"); err != nil {
					return nil, err
				}
				if err := rejectEmpty(c, "NewPath", "NewGroupName"); err != nil {
					return nil, err
				}
				if err := authorizeMovedGroup(h, c); err != nil {
					return nil, err
				}
				return nil, h.cfg.Admin.UpdateGroup(
					c.r.Context(), c.caller.Account, c.form("GroupName"), c.form("NewPath"), c.form("NewGroupName"),
					c.authorized)
			},
		),
		"DeleteGroup": admin([]string{"GroupName"}, groupARN, func(h *handler, c *exchange) (any, error) {
			if err := required(c, "GroupName"); err != nil {
				return nil, err
			}
			return nil, h.cfg.Admin.DeleteGroup(c.r.Context(), c.caller.Account, c.form("GroupName"), c.authorized)
		}),
		"AddUserToGroup": admin([]string{"GroupName", "UserName"}, groupARN, func(h *handler, c *exchange) (any, error) {
			if err := required(c, "GroupName", "UserName"); err != nil {
				return nil, err
			}
			return nil, h.cfg.Admin.AddUserToGroup(
				c.r.Context(), c.caller.Account, c.form("GroupName"), c.form("UserName"), c.authorized)
		}),
		"RemoveUserFromGroup": admin([]string{"GroupName", "UserName"}, groupARN, func(h *handler, c *exchange) (any, error) {
			if err := required(c, "GroupName", "UserName"); err != nil {
				return nil, err
			}
			return nil, h.cfg.Admin.RemoveUserFromGroup(
				c.r.Context(), c.caller.Account, c.form("GroupName"), c.form("UserName"), c.authorized)
		}),
		"ListGroupsForUser": {params: []string{"UserName"}, list: true, needsAdmin: true, resource: userARN, run: func(h *handler, c *exchange) (any, error) {
			if err := required(c, "UserName"); err != nil {
				return nil, err
			}
			if _, _, err := pageParams(c); err != nil {
				return nil, err
			}
			gs, err := h.cfg.Admin.ListGroupsForUser(c.r.Context(), c.caller.Account, c.form("UserName"), c.authorized)
			if err != nil {
				return nil, err
			}
			return pagedGroups(c, gs)
		}},

		"CreateRole": admin([]string{"RoleName", "Path", "AssumeRolePolicyDocument", "Description", "MaxSessionDuration"}, roleARN, func(h *handler, c *exchange) (any, error) {
			if err := required(c, "RoleName", "AssumeRolePolicyDocument"); err != nil {
				return nil, err
			}
			maxSession := 0
			if raw := c.form("MaxSessionDuration"); raw != "" {
				n, err := strconv.Atoi(raw)
				if err != nil {
					return nil, resource.Invalid("maxSessionDuration", "must be a number")
				}
				maxSession = n
			}
			r, err := h.cfg.Admin.CreateRole(c.r.Context(), c.caller.Account, iam.RoleInput{
				Name: c.form("RoleName"), Path: c.form("Path"), TrustPolicy: c.form("AssumeRolePolicyDocument"),
				Description: c.form("Description"), MaxSessionDuration: maxSession,
			})
			return struct {
				Role roleXML `xml:"Role"`
			}{toRole(r)}, err
		}),
		"GetRole": admin([]string{"RoleName"}, roleARN, func(h *handler, c *exchange) (any, error) {
			// A role replaced on another path since it was authorized is
			// not shown.
			r, err := h.cfg.Admin.GetRole(c.r.Context(), c.caller.Account, c.form("RoleName"), c.authorized)
			if err != nil {
				return nil, err
			}
			return struct {
				Role roleXML `xml:"Role"`
			}{toRole(r)}, nil
		}),
		"UpdateRole": admin(
			[]string{"RoleName", "Description", "MaxSessionDuration"}, roleARN,
			func(h *handler, c *exchange) (any, error) {
				if err := required(c, "RoleName"); err != nil {
					return nil, err
				}
				var in iam.RoleUpdate
				if c.r.Form.Has("Description") {
					description := c.form("Description")
					in.Description = &description
				}
				if c.r.Form.Has("MaxSessionDuration") {
					seconds, err := strconv.Atoi(c.form("MaxSessionDuration"))
					if err != nil {
						return nil, resource.Invalid("maxSessionDuration", "must be a number")
					}
					in.MaxSessionDuration = &seconds
				}
				if err := h.cfg.Admin.UpdateRole(
					c.r.Context(), c.caller.Account, c.form("RoleName"), in, c.authorized); err != nil {
					return nil, err
				}
				// AWS keeps the empty UpdateRoleResult wrapper, and SDKs
				// expect it.
				return struct{}{}, nil
			},
		),
		"UpdateRoleDescription": admin(
			[]string{"RoleName", "Description"}, roleARN,
			func(h *handler, c *exchange) (any, error) {
				if err := required(c, "RoleName", "Description"); err != nil {
					return nil, err
				}
				r, err := h.cfg.Admin.UpdateRoleDescription(
					c.r.Context(), c.caller.Account, c.form("RoleName"), c.form("Description"), c.authorized)
				return struct {
					Role roleXML `xml:"Role"`
				}{toRole(r)}, err
			},
		),
		"ListRoles": lister(nil, func(h *handler, c *exchange) (any, error) {
			rs, err := h.cfg.Admin.ListRoles(c.r.Context(), c.caller.Account, c.form("PathPrefix"))
			out := rolesResult{Roles: []roleXML{}}
			for _, r := range rs {
				out.Roles = append(out.Roles, toRole(r))
			}
			return out, err
		}),
		"UpdateAssumeRolePolicy": admin(
			[]string{"RoleName", "PolicyDocument"}, roleARN,
			func(h *handler, c *exchange) (any, error) {
				if err := required(c, "RoleName", "PolicyDocument"); err != nil {
					return nil, err
				}
				return nil, h.cfg.Admin.UpdateAssumeRolePolicy(
					c.r.Context(), c.caller.Account, c.form("RoleName"), c.form("PolicyDocument"), c.authorized)
			},
		),
		"DeleteRole": admin([]string{"RoleName"}, roleARN, func(h *handler, c *exchange) (any, error) {
			return nil, h.cfg.Admin.DeleteRole(c.r.Context(), c.caller.Account, c.form("RoleName"), c.authorized)
		}),

		"CreatePolicy": admin([]string{"PolicyName", "Path", "PolicyDocument", "Description"}, policyARN, func(h *handler, c *exchange) (any, error) {
			if err := required(c, "PolicyName", "PolicyDocument"); err != nil {
				return nil, err
			}
			p, err := h.cfg.Admin.CreatePolicy(c.r.Context(), c.caller.Account, c.form("PolicyName"), c.form("Path"), c.form("PolicyDocument"), c.form("Description"))
			return struct {
				Policy policyXML `xml:"Policy"`
			}{toPolicy(p)}, err
		}),
		"GetPolicy": admin([]string{"PolicyArn"}, policyARN, func(h *handler, c *exchange) (any, error) {
			p, err := h.cfg.Admin.GetPolicy(c.r.Context(), c.caller.Account, c.form("PolicyArn"))
			return struct {
				Policy policyXML `xml:"Policy"`
			}{toPolicy(p)}, err
		}),
		"GetPolicyVersion": admin([]string{"PolicyArn", "VersionId"}, policyARN, func(h *handler, c *exchange) (any, error) {
			v, err := h.cfg.Admin.GetPolicyVersion(
				c.r.Context(), c.caller.Account, c.form("PolicyArn"), c.form("VersionId"))
			return struct {
				PolicyVersion policyVersionXML `xml:"PolicyVersion"`
			}{policyVersionXML{
				Document: policyDoc(v.Document), VersionID: v.ID,
				IsDefaultVersion: v.IsDefaultVersion, CreateDate: stamp(v.Created),
			}}, err
		}),
		"CreatePolicyVersion": admin([]string{"PolicyArn", "PolicyDocument", "SetAsDefault"}, policyARN,
			func(h *handler, c *exchange) (any, error) {
				if err := required(c, "PolicyArn", "PolicyDocument"); err != nil {
					return nil, err
				}
				if !policyARNRE.MatchString(c.form("PolicyArn")) {
					return nil, resource.Invalid("policyArn", "The policy ARN '"+c.form("PolicyArn")+"' is not valid.")
				}
				setAsDefault := false
				switch c.form("SetAsDefault") {
				case "", "false":
				case "true":
					setAsDefault = true
				default:
					return nil, resource.Invalid("SetAsDefault", "The specified value for setAsDefault is invalid.")
				}
				v, err := h.cfg.Admin.CreatePolicyVersion(
					c.r.Context(), c.caller.Account, c.form("PolicyArn"), c.form("PolicyDocument"), setAsDefault)
				return struct {
					PolicyVersion policyVersionXML `xml:"PolicyVersion"`
				}{policyVersionXML{
					VersionID: v.ID, IsDefaultVersion: v.IsDefaultVersion, CreateDate: stamp(v.Created),
				}}, err
			},
		),
		"ListPolicyVersions": {
			params: []string{"PolicyArn", "Marker", "MaxItems"}, needsAdmin: true, resource: policyARN,
			run: func(h *handler, c *exchange) (any, error) {
				if err := requirePolicyArn(c, h, "iam:ListPolicyVersions"); err != nil {
					return nil, err
				}
				maxItems, err := maxItemsParam(c)
				if err != nil {
					return nil, err
				}
				if err := markerParam(c); err != nil {
					return nil, err
				}
				page, err := h.cfg.Admin.ListPolicyVersions(
					c.r.Context(), c.caller.Account, c.form("PolicyArn"), c.form("Marker"), maxItems)
				out := policyVersionsResult{
					Versions:    []policyVersionXML{},
					IsTruncated: page.IsTruncated,
					Marker:      page.Marker,
				}
				for _, v := range page.Versions {
					out.Versions = append(out.Versions, policyVersionXML{
						VersionID: v.ID, IsDefaultVersion: v.IsDefaultVersion, CreateDate: stamp(v.Created),
					})
				}
				return out, err
			},
		},
		"SetDefaultPolicyVersion": admin([]string{"PolicyArn", "VersionId"}, policyARN,
			func(h *handler, c *exchange) (any, error) {
				if err := required(c, "PolicyArn", "VersionId"); err != nil {
					return nil, err
				}
				if !policyVersionRE.MatchString(c.form("VersionId")) {
					return nil, resource.Invalid("VersionId", "The specified value for versionId is invalid.")
				}
				return nil, h.cfg.Admin.SetDefaultPolicyVersion(
					c.r.Context(), c.caller.Account, c.form("PolicyArn"), c.form("VersionId"))
			},
		),
		"DeletePolicyVersion": admin([]string{"PolicyArn", "VersionId"}, policyARN,
			func(h *handler, c *exchange) (any, error) {
				if err := required(c, "PolicyArn", "VersionId"); err != nil {
					return nil, err
				}
				if !policyARNRE.MatchString(c.form("PolicyArn")) {
					return nil, resource.Invalid("policyArn", "The policy ARN '"+c.form("PolicyArn")+"' is not valid.")
				}
				if !policyVersionRE.MatchString(c.form("VersionId")) {
					// The capital field name makes the surface answer InvalidInput,
					// as the AWS reference documents for this action.
					return nil, resource.Invalid("VersionId", "The policy version id '"+c.form("VersionId")+"' is not valid.")
				}
				return nil, h.cfg.Admin.DeletePolicyVersion(
					c.r.Context(), c.caller.Account, c.form("PolicyArn"), c.form("VersionId"))
			},
		),
		"ListPolicies": {params: []string{"Scope", "OnlyAttached", "PolicyUsageFilter"}, list: true, needsAdmin: true, run: func(h *handler, c *exchange) (any, error) {
			out := policiesResult{Policies: []policyXML{}}
			if c.form("Scope") == "AWS" { // no AWS managed policies exist here
				return out, nil
			}
			ps, err := h.cfg.Admin.ListPolicies(c.r.Context(), c.caller.Account, c.form("PathPrefix"))
			for _, p := range ps {
				if c.form("OnlyAttached") == "true" && p.AttachmentCount == 0 {
					continue
				}
				out.Policies = append(out.Policies, toPolicy(p))
			}
			return out, err
		}},
		"DeletePolicy": admin([]string{"PolicyArn"}, policyARN, func(h *handler, c *exchange) (any, error) {
			return nil, h.cfg.Admin.DeletePolicy(c.r.Context(), c.caller.Account, c.form("PolicyArn"))
		}),
		"TagPolicy": {
			params: []string{"PolicyArn"}, prefixes: []string{"Tags.member."}, needsAdmin: true,
			resource: policyARN,
			run: func(h *handler, c *exchange) (any, error) {
				if err := requirePolicyArn(c, h, "iam:TagPolicy"); err != nil {
					return nil, err
				}
				tags, err := parseTagMembers(c)
				if err != nil {
					return nil, err
				}
				return nil, h.cfg.Admin.TagPolicy(c.r.Context(), c.caller.Account, c.form("PolicyArn"), tags)
			},
		},
		"UntagPolicy": {
			params: []string{"PolicyArn"}, prefixes: []string{"TagKeys.member."}, needsAdmin: true,
			resource: policyARN,
			run: func(h *handler, c *exchange) (any, error) {
				if err := requirePolicyArn(c, h, "iam:UntagPolicy"); err != nil {
					return nil, err
				}
				keys, err := parseTagKeys(c)
				if err != nil {
					return nil, err
				}
				return nil, h.cfg.Admin.UntagPolicy(c.r.Context(), c.caller.Account, c.form("PolicyArn"), keys)
			},
		},
		"ListPolicyTags": {
			params: []string{"PolicyArn", "Marker", "MaxItems"}, needsAdmin: true, resource: policyARN,
			run: func(h *handler, c *exchange) (any, error) {
				if err := requirePolicyArn(c, h, "iam:ListPolicyTags"); err != nil {
					return nil, err
				}
				maxItems, err := maxItemsParam(c)
				if err != nil {
					return nil, err
				}
				if err := markerParam(c); err != nil {
					return nil, err
				}
				page, err := h.cfg.Admin.ListPolicyTags(
					c.r.Context(), c.caller.Account, c.form("PolicyArn"), c.form("Marker"), maxItems)
				out := tagsResult{Tags: []tagXML{}, IsTruncated: page.IsTruncated, Marker: page.Marker}
				for _, tag := range page.Tags {
					out.Tags = append(out.Tags, tagXML{Key: tag.Key, Value: tag.Value})
				}
				return out, err
			},
		},
		"ListVirtualMFADevices": {
			params: []string{"AssignmentStatus", "Marker", "MaxItems"}, needsAdmin: true,
			run: func(h *handler, c *exchange) (any, error) {
				assignment, err := assignmentStatusParam(c)
				if err != nil {
					return nil, err
				}
				maxItems, err := maxItemsParam(c)
				if err != nil {
					return nil, err
				}
				if err := mfaDeviceMarkerParam(c); err != nil {
					return nil, err
				}
				page, err := h.cfg.Admin.ListVirtualMFADevices(
					c.r.Context(), c.caller.Account, assignment, c.form("Marker"), maxItems)
				out := virtualMFADevicesResult{
					VirtualMFADevices: []virtualMFADeviceXML{},
					IsTruncated:       page.IsTruncated,
					Marker:            page.Marker,
				}
				for _, d := range page.Devices {
					out.VirtualMFADevices = append(out.VirtualMFADevices, toVirtualMFADevice(d))
				}
				return out, err
			},
		},
		// AWS ListMFADevices is authorized on the user, the named one or else
		// the caller, so a policy on user/${aws:username} covers only the
		// caller's own devices. It takes Marker and MaxItems but not
		// PathPrefix, so the spec lists them rather than setting list.
		"ListMFADevices": {
			params: []string{"UserName", "Marker", "MaxItems"}, needsAdmin: true, resource: listMFADevicesARN,
			run: func(h *handler, c *exchange) (any, error) {
				user, err := listMFADevicesUserName(c)
				if err != nil {
					return nil, err
				}
				maxItems, err := maxItemsParam(c)
				if err != nil {
					return nil, err
				}
				if err := mfaDeviceMarkerParam(c); err != nil {
					return nil, err
				}
				// The backend reads only the user at the authorized ARN, so a
				// user moved since the authorization lists nothing.
				page, err := h.cfg.Admin.ListMFADevices(
					c.r.Context(), c.caller.Account, user, c.form("Marker"), maxItems, c.authorized)
				if err != nil {
					return nil, err
				}
				out := mfaDevicesResult{
					MFADevices:  []listedMFADeviceXML{},
					IsTruncated: page.IsTruncated,
					Marker:      page.Marker,
				}
				for _, d := range page.Devices {
					out.MFADevices = append(out.MFADevices, toListedMFADevice(d))
				}
				return out, nil
			},
		},
		// AWS GetMFADevice is authorized on the user, the named one or else the
		// caller, and accepts only FIDO security key serial numbers. No
		// backend holds FIDO keys yet, so an authorized call answers
		// NoSuchEntity for every serial number, a virtual mfa/ device
		// included.
		"GetMFADevice": {
			params: []string{"SerialNumber", "UserName"}, needsAdmin: true, resource: getMFADeviceARN,
			run: func(h *handler, c *exchange) (any, error) {
				if err := requireMFADevice(c, h, "iam:GetMFADevice"); err != nil {
					return nil, err
				}
				dev, err := h.cfg.Admin.GetMFADevice(c.r.Context(), c.caller.Account, c.form("SerialNumber"))
				if err != nil {
					return nil, err
				}
				// AWS names the device's user in the answer; a UserName that
				// names another user does not have this device.
				if user := c.form("UserName"); user != "" && user != dev.UserName {
					return nil, iam.MFADeviceNotFound()
				}
				return toMFADevice(dev), nil
			},
		},
		"TagMFADevice": {
			params: []string{"SerialNumber"}, prefixes: []string{"Tags.member."}, needsAdmin: true,
			resource: mfaDeviceARN,
			run: func(h *handler, c *exchange) (any, error) {
				if err := requireMFADevice(c, h, "iam:TagMFADevice"); err != nil {
					return nil, err
				}
				tags, err := parseTagMembers(c)
				if err != nil {
					return nil, err
				}
				return nil, h.cfg.Admin.TagMFADevice(c.r.Context(), c.caller.Account, c.form("SerialNumber"), tags)
			},
		},
		"UntagMFADevice": {
			params: []string{"SerialNumber"}, prefixes: []string{"TagKeys.member."}, needsAdmin: true,
			resource: mfaDeviceARN,
			run: func(h *handler, c *exchange) (any, error) {
				if err := requireMFADevice(c, h, "iam:UntagMFADevice"); err != nil {
					return nil, err
				}
				keys, err := parseTagKeys(c)
				if err != nil {
					return nil, err
				}
				return nil, h.cfg.Admin.UntagMFADevice(c.r.Context(), c.caller.Account, c.form("SerialNumber"), keys)
			},
		},
		"ListMFADeviceTags": {
			params: []string{"SerialNumber", "Marker", "MaxItems"}, needsAdmin: true, resource: mfaDeviceARN,
			run: func(h *handler, c *exchange) (any, error) {
				if err := requireMFADevice(c, h, "iam:ListMFADeviceTags"); err != nil {
					return nil, err
				}
				maxItems, err := maxItemsParam(c)
				if err != nil {
					return nil, err
				}
				if err := markerParam(c); err != nil {
					return nil, err
				}
				page, err := h.cfg.Admin.ListMFADeviceTags(
					c.r.Context(), c.caller.Account, c.form("SerialNumber"), c.form("Marker"), maxItems)
				out := tagsResult{Tags: []tagXML{}, IsTruncated: page.IsTruncated, Marker: page.Marker}
				for _, tag := range page.Tags {
					out.Tags = append(out.Tags, tagXML{Key: tag.Key, Value: tag.Value})
				}
				return out, err
			},
		},
	}
	for kind, e := range map[iam.Entity]struct {
		word, key string
		arn       func(h *handler, c *exchange) string
	}{
		iam.EntityUser:  {"User", "UserName", userARN},
		iam.EntityGroup: {"Group", "GroupName", groupARN},
		iam.EntityRole:  {"Role", "RoleName", roleARN},
	} {
		kind, e := kind, e
		m["Attach"+e.word+"Policy"] = admin([]string{e.key, "PolicyArn"}, e.arn, func(h *handler, c *exchange) (any, error) {
			if err := required(c, e.key); err != nil {
				return nil, err
			}
			if err := policyArnParam(c); err != nil {
				return nil, err
			}
			return nil, h.cfg.Admin.AttachPolicy(
				c.r.Context(), c.caller.Account, kind, c.form(e.key), c.form("PolicyArn"), c.authorized)
		})
		m["Detach"+e.word+"Policy"] = admin([]string{e.key, "PolicyArn"}, e.arn, func(h *handler, c *exchange) (any, error) {
			if err := required(c, e.key); err != nil {
				return nil, err
			}
			if err := policyArnParam(c); err != nil {
				return nil, err
			}
			return nil, h.cfg.Admin.DetachPolicy(
				c.r.Context(), c.caller.Account, kind, c.form(e.key), c.form("PolicyArn"), c.authorized)
		})
		m["ListAttached"+e.word+"Policies"] = spec{params: []string{e.key}, list: true, needsAdmin: true, resource: e.arn, run: func(h *handler, c *exchange) (any, error) {
			if err := required(c, e.key); err != nil {
				return nil, err
			}
			marker, maxItems, err := pageParams(c)
			if err != nil {
				return nil, err
			}
			prefix, err := attachedPathPrefixParam(c)
			if err != nil {
				return nil, err
			}
			ps, err := h.cfg.Admin.ListAttachedPolicies(c.r.Context(), c.caller.Account, kind, c.form(e.key), c.authorized)
			if err != nil {
				return nil, err
			}
			ps = slices.DeleteFunc(ps, func(p iam.ManagedPolicy) bool { return !strings.HasPrefix(p.Path, prefix) })
			page, truncated, next := pageByName(ps, func(p iam.ManagedPolicy) string { return p.Name }, marker, maxItems)
			out := attachedResult{AttachedPolicies: []attachedXML{}, IsTruncated: truncated, Marker: next}
			for _, p := range page {
				out.AttachedPolicies = append(out.AttachedPolicies, attachedXML{PolicyName: p.Name, PolicyArn: p.ARN})
			}
			return out, nil
		}}
		m["Put"+e.word+"Policy"] = admin([]string{e.key, "PolicyName", "PolicyDocument"}, e.arn, func(h *handler, c *exchange) (any, error) {
			if err := required(c, e.key); err != nil {
				return nil, err
			}
			if err := inlinePolicyNameParam(c); err != nil {
				return nil, err
			}
			if err := policyDocumentParam(c); err != nil {
				return nil, err
			}
			return nil, h.cfg.Admin.PutInlinePolicy(c.r.Context(), c.caller.Account, kind, c.form(e.key),
				c.form("PolicyName"), c.form("PolicyDocument"), c.authorized)
		})
		m["Get"+e.word+"Policy"] = admin([]string{e.key, "PolicyName"}, e.arn, func(h *handler, c *exchange) (any, error) {
			if err := required(c, e.key); err != nil {
				return nil, err
			}
			if err := inlinePolicyNameParam(c); err != nil {
				return nil, err
			}
			doc, err := h.cfg.Admin.GetInlinePolicy(
				c.r.Context(), c.caller.Account, kind, c.form(e.key), c.form("PolicyName"), c.authorized)
			if err != nil {
				return nil, err
			}
			out := struct {
				Entity         string `xml:",innerxml"`
				PolicyName     string `xml:"PolicyName"`
				PolicyDocument string `xml:"PolicyDocument"`
			}{PolicyName: c.form("PolicyName"), PolicyDocument: policyDoc(doc)}
			out.Entity = "<" + e.key + ">" + xmlEscape(c.form(e.key)) + "</" + e.key + ">"
			return out, nil
		})
		m["Delete"+e.word+"Policy"] = admin([]string{e.key, "PolicyName"}, e.arn, func(h *handler, c *exchange) (any, error) {
			if err := required(c, e.key); err != nil {
				return nil, err
			}
			if err := inlinePolicyNameParam(c); err != nil {
				return nil, err
			}
			return nil, h.cfg.Admin.DeleteInlinePolicy(
				c.r.Context(), c.caller.Account, kind, c.form(e.key), c.form("PolicyName"), c.authorized)
		})
		// AWS List*Policies takes Marker and MaxItems but no PathPrefix.
		listInline := []string{e.key, "Marker", "MaxItems"}
		m["List"+e.word+"Policies"] = admin(listInline, e.arn, func(h *handler, c *exchange) (any, error) {
			if err := required(c, e.key); err != nil {
				return nil, err
			}
			marker, maxItems, err := pageParams(c)
			if err != nil {
				return nil, err
			}
			names, err := h.cfg.Admin.ListInlinePolicies(c.r.Context(), c.caller.Account, kind, c.form(e.key), c.authorized)
			if err != nil {
				return nil, err
			}
			page, truncated, next := pageByName(names, func(n string) string { return n }, marker, maxItems)
			return namesResult{PolicyNames: page, IsTruncated: truncated, Marker: next}, nil
		})
	}
	return m
}

func stsActions() map[string]spec {
	return map[string]spec{
		"GetCallerIdentity": {public: true, run: func(h *handler, c *exchange) (any, error) {
			return struct {
				Arn     string `xml:"Arn"`
				UserID  string `xml:"UserId"`
				Account string `xml:"Account"`
			}{c.caller.Principal, callerID(h, c), c.caller.Account.String()}, nil
		}},
		"AssumeRole": {
			params: []string{"RoleArn", "RoleSessionName", "DurationSeconds"}, needsAdmin: true,
			resource: func(_ *handler, c *exchange) string { return c.form("RoleArn") },
			run: func(h *handler, c *exchange) (any, error) {
				if err := required(c, "RoleArn", "RoleSessionName"); err != nil {
					return nil, err
				}
				var d time.Duration
				if raw := c.form("DurationSeconds"); raw != "" {
					n, err := strconv.Atoi(raw)
					if err != nil || n < 900 {
						return nil, resource.Invalid("durationSeconds", "1 validation error detected: Value '"+raw+"' at 'durationSeconds' failed to satisfy constraint: Member must have value greater than or equal to 900")
					}
					d = time.Duration(n) * time.Second
				}
				got, err := h.cfg.Admin.AssumeRole(c.r.Context(), iam.Principal{Account: c.caller.Account, ARN: c.caller.Principal, Root: c.caller.Root, Ref: c.caller.Ref}, c.form("RoleArn"), c.form("RoleSessionName"), d)
				if err != nil {
					return nil, err
				}
				return struct {
					Credentials credentialsXML `xml:"Credentials"`
					RoleID      string         `xml:"AssumedRoleUser>AssumedRoleId"`
					Arn         string         `xml:"AssumedRoleUser>Arn"`
				}{
					credentialsXML{
						AccessKeyID:     got.Key.AccessKey,
						SecretAccessKey: got.Key.Secret,
						SessionToken:    got.Key.SessionToken,
						Expiration:      stamp(got.Key.Expires),
					},
					got.AssumedRoleID, got.ARN,
				}, nil
			},
		},
	}
}

// callerID is the AWS UserId: the account id for root, the user id for a
// user, and role-id:session for an assumed role.
func callerID(h *handler, c *exchange) string {
	if c.caller.Root {
		return c.caller.Account.String()
	}
	if h.cfg.Admin == nil {
		return c.caller.Subject
	}
	if _, rest, ok := strings.Cut(c.caller.Principal, ":assumed-role/"); ok {
		role, session, _ := strings.Cut(rest, "/")
		if r, err := h.cfg.Admin.ResolveRole(c.r.Context(), c.caller.Account, role); err == nil {
			return r.ID + ":" + session
		}
	}
	if n := userName(c); n != "" {
		if u, err := h.cfg.Admin.ResolveUser(c.r.Context(), c.caller.Account, n); err == nil && u.ARN == c.caller.Principal {
			return u.ID
		}
	}
	return c.caller.Subject
}

func xmlEscape(s string) string {
	var b strings.Builder
	if err := xml.EscapeText(&b, []byte(s)); err != nil {
		return ""
	}
	return b.String()
}

// loginProfileInput requires UserName and Password. PasswordResetRequired=true
// needs the sign-in password change flow, which is not built yet.
func loginProfileInput(c *exchange) error {
	if err := required(c, "UserName", "Password"); err != nil {
		return err
	}
	if v := c.form("PasswordResetRequired"); v != "" && v != "false" {
		return resource.Invalid("PasswordResetRequired", "PasswordResetRequired=true is not supported yet")
	}
	return nil
}
