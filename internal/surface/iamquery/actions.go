package iamquery

import (
	"encoding/xml"
	"strconv"
	"strings"
	"time"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

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
func userARN(h *handler, c *exchange) string {
	name := userName(c)
	if name == "" {
		return c.caller.Principal
	}
	if c.action == "CreateUser" {
		return arnOf(c, "user", pathOr(c.form("Path")), name)
	}
	if u, err := h.cfg.Admin.GetUser(c.r.Context(), c.caller.Account, name); err == nil {
		return u.ARN
	}
	return arnOf(c, "user", "/", name)
}

func groupARN(h *handler, c *exchange) string {
	name := c.form("GroupName")
	if c.action == "CreateGroup" {
		return arnOf(c, "group", pathOr(c.form("Path")), name)
	}
	if g, _, err := h.cfg.Admin.GetGroup(c.r.Context(), c.caller.Account, name); err == nil {
		return g.ARN
	}
	return arnOf(c, "group", "/", name)
}

func roleARN(h *handler, c *exchange) string {
	name := c.form("RoleName")
	if c.action == "CreateRole" {
		return arnOf(c, "role", pathOr(c.form("Path")), name)
	}
	if r, err := h.cfg.Admin.GetRole(c.r.Context(), c.caller.Account, name); err == nil {
		return r.ARN
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

func required(c *exchange, keys ...string) error {
	for _, k := range keys {
		if c.form(k) == "" {
			return resource.Invalid(lowerFirst(k), "1 validation error detected: Value null at '"+lowerFirst(k)+"' failed to satisfy constraint: Member must not be null")
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
}

type groupsResult struct {
	Groups      []groupXML `xml:"Groups>member"`
	IsTruncated bool       `xml:"IsTruncated"`
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
}

type namesResult struct {
	PolicyNames []string `xml:"PolicyNames>member"`
	IsTruncated bool     `xml:"IsTruncated"`
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
			u, err := h.cfg.Admin.GetUser(c.r.Context(), c.caller.Account, name)
			return struct {
				User userXML `xml:"User"`
			}{toUser(u)}, err
		}),
		"ListUsers": lister(nil, func(h *handler, c *exchange) (any, error) {
			us, err := h.cfg.Admin.ListUsers(c.r.Context(), c.caller.Account, c.form("PathPrefix"))
			out := usersResult{Users: []userXML{}}
			for _, u := range us {
				out.Users = append(out.Users, toUser(u))
			}
			return out, err
		}),
		"DeleteUser": admin([]string{"UserName"}, userARN, func(h *handler, c *exchange) (any, error) {
			if err := required(c, "UserName"); err != nil {
				return nil, err
			}
			return nil, h.cfg.Admin.DeleteUser(c.r.Context(), c.caller.Account, c.form("UserName"))
		}),
		"CreateLoginProfile": admin([]string{"UserName", "Password", "PasswordResetRequired"}, userARN, func(h *handler, c *exchange) (any, error) {
			if err := loginProfileInput(c); err != nil {
				return nil, err
			}
			p, err := h.cfg.Admin.CreateLoginProfile(c.r.Context(), c.caller.Account, c.form("UserName"), c.form("Password"))
			return struct {
				LoginProfile loginProfileXML `xml:"LoginProfile"`
			}{toLoginProfile(p)}, err
		}),
		"GetLoginProfile": admin([]string{"UserName"}, userARN, func(h *handler, c *exchange) (any, error) {
			if err := required(c, "UserName"); err != nil {
				return nil, err
			}
			p, err := h.cfg.Admin.GetLoginProfile(c.r.Context(), c.caller.Account, c.form("UserName"))
			return struct {
				LoginProfile loginProfileXML `xml:"LoginProfile"`
			}{toLoginProfile(p)}, err
		}),
		"UpdateLoginProfile": admin([]string{"UserName", "Password", "PasswordResetRequired"}, userARN, func(h *handler, c *exchange) (any, error) {
			if err := loginProfileInput(c); err != nil {
				return nil, err
			}
			return nil, h.cfg.Admin.UpdateLoginProfile(c.r.Context(), c.caller.Account, c.form("UserName"), c.form("Password"))
		}),
		"DeleteLoginProfile": admin([]string{"UserName"}, userARN, func(h *handler, c *exchange) (any, error) {
			if err := required(c, "UserName"); err != nil {
				return nil, err
			}
			return nil, h.cfg.Admin.DeleteLoginProfile(c.r.Context(), c.caller.Account, c.form("UserName"))
		}),
		"CreateAccessKey": admin([]string{"UserName"}, userARN, func(h *handler, c *exchange) (any, error) {
			n, err := requireUser(c)
			if err != nil {
				return nil, err
			}
			k, err := h.cfg.Admin.CreateAccessKey(c.r.Context(), c.caller.Account, n)
			return struct {
				AccessKey accessKeyXML `xml:"AccessKey"`
			}{accessKeyXML{UserName: k.UserName, AccessKeyID: k.AccessKeyID, Status: k.Status, SecretAccessKey: k.Secret, CreateDate: stamp(k.Created)}}, err
		}),
		"ListAccessKeys": {params: []string{"UserName"}, list: true, needsAdmin: true, resource: userARN, run: func(h *handler, c *exchange) (any, error) {
			n, err := requireUser(c)
			if err != nil {
				return nil, err
			}
			ks, err := h.cfg.Admin.ListAccessKeys(c.r.Context(), c.caller.Account, n)
			out := struct {
				Keys        []keyMetaXML `xml:"AccessKeyMetadata>member"`
				UserName    string       `xml:"UserName"`
				IsTruncated bool         `xml:"IsTruncated"`
			}{Keys: []keyMetaXML{}, UserName: n}
			for _, k := range ks {
				out.Keys = append(out.Keys, keyMetaXML{UserName: k.UserName, AccessKeyID: k.AccessKeyID, Status: k.Status, CreateDate: stamp(k.Created)})
			}
			return out, err
		}},
		"DeleteAccessKey": admin([]string{"UserName", "AccessKeyId"}, userARN, func(h *handler, c *exchange) (any, error) {
			n, err := requireUser(c)
			if err != nil {
				return nil, err
			}
			if err := required(c, "AccessKeyId"); err != nil {
				return nil, err
			}
			return nil, h.cfg.Admin.DeleteAccessKey(c.r.Context(), c.caller.Account, n, c.form("AccessKeyId"))
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
			g, us, err := h.cfg.Admin.GetGroup(c.r.Context(), c.caller.Account, c.form("GroupName"))
			out := struct {
				Group       groupXML  `xml:"Group"`
				Users       []userXML `xml:"Users>member"`
				IsTruncated bool      `xml:"IsTruncated"`
			}{Group: toGroup(g), Users: []userXML{}}
			for _, u := range us {
				out.Users = append(out.Users, toUser(u))
			}
			return out, err
		}},
		"ListGroups": lister(nil, func(h *handler, c *exchange) (any, error) {
			gs, err := h.cfg.Admin.ListGroups(c.r.Context(), c.caller.Account, c.form("PathPrefix"))
			out := groupsResult{Groups: []groupXML{}}
			for _, g := range gs {
				out.Groups = append(out.Groups, toGroup(g))
			}
			return out, err
		}),
		"DeleteGroup": admin([]string{"GroupName"}, groupARN, func(h *handler, c *exchange) (any, error) {
			return nil, h.cfg.Admin.DeleteGroup(c.r.Context(), c.caller.Account, c.form("GroupName"))
		}),
		"AddUserToGroup": admin([]string{"GroupName", "UserName"}, groupARN, func(h *handler, c *exchange) (any, error) {
			if err := required(c, "GroupName", "UserName"); err != nil {
				return nil, err
			}
			return nil, h.cfg.Admin.AddUserToGroup(c.r.Context(), c.caller.Account, c.form("GroupName"), c.form("UserName"))
		}),
		"RemoveUserFromGroup": admin([]string{"GroupName", "UserName"}, groupARN, func(h *handler, c *exchange) (any, error) {
			if err := required(c, "GroupName", "UserName"); err != nil {
				return nil, err
			}
			return nil, h.cfg.Admin.RemoveUserFromGroup(c.r.Context(), c.caller.Account, c.form("GroupName"), c.form("UserName"))
		}),
		"ListGroupsForUser": {params: []string{"UserName"}, list: true, needsAdmin: true, resource: userARN, run: func(h *handler, c *exchange) (any, error) {
			gs, err := h.cfg.Admin.ListGroupsForUser(c.r.Context(), c.caller.Account, c.form("UserName"))
			out := groupsResult{Groups: []groupXML{}}
			for _, g := range gs {
				out.Groups = append(out.Groups, toGroup(g))
			}
			return out, err
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
			r, err := h.cfg.Admin.GetRole(c.r.Context(), c.caller.Account, c.form("RoleName"))
			return struct {
				Role roleXML `xml:"Role"`
			}{toRole(r)}, err
		}),
		"ListRoles": lister(nil, func(h *handler, c *exchange) (any, error) {
			rs, err := h.cfg.Admin.ListRoles(c.r.Context(), c.caller.Account, c.form("PathPrefix"))
			out := rolesResult{Roles: []roleXML{}}
			for _, r := range rs {
				out.Roles = append(out.Roles, toRole(r))
			}
			return out, err
		}),
		"DeleteRole": admin([]string{"RoleName"}, roleARN, func(h *handler, c *exchange) (any, error) {
			return nil, h.cfg.Admin.DeleteRole(c.r.Context(), c.caller.Account, c.form("RoleName"))
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
			p, err := h.cfg.Admin.GetPolicy(c.r.Context(), c.caller.Account, c.form("PolicyArn"))
			if err != nil {
				return nil, err
			}
			if c.form("VersionId") != "v1" {
				return nil, &resource.Error{Code: resource.CodeNotFound, Message: "Policy " + p.ARN + " version " + c.form("VersionId") + " does not exist or is not attachable."}
			}
			return struct {
				PolicyVersion policyVersionXML `xml:"PolicyVersion"`
			}{policyVersionXML{Document: policyDoc(p.Document), VersionID: "v1", IsDefaultVersion: true, CreateDate: stamp(p.Created)}}, nil
		}),
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
				if err := iam.ValidateTags(tags); err != nil {
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
				for _, key := range keys {
					if err := iam.ValidateTagKey(key); err != nil {
						return nil, err
					}
				}
				return nil, h.cfg.Admin.UntagPolicy(c.r.Context(), c.caller.Account, c.form("PolicyArn"), keys)
			},
		},
		"ListPolicyTags": {
			params: []string{"PolicyArn"}, list: true, needsAdmin: true, resource: policyARN,
			run: func(h *handler, c *exchange) (any, error) {
				if err := requirePolicyArn(c, h, "iam:ListPolicyTags"); err != nil {
					return nil, err
				}
				maxItems, err := maxItemsParam(c)
				if err != nil {
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
			if err := required(c, e.key, "PolicyArn"); err != nil {
				return nil, err
			}
			return nil, h.cfg.Admin.AttachPolicy(c.r.Context(), c.caller.Account, kind, c.form(e.key), c.form("PolicyArn"))
		})
		m["Detach"+e.word+"Policy"] = admin([]string{e.key, "PolicyArn"}, e.arn, func(h *handler, c *exchange) (any, error) {
			if err := required(c, e.key, "PolicyArn"); err != nil {
				return nil, err
			}
			return nil, h.cfg.Admin.DetachPolicy(c.r.Context(), c.caller.Account, kind, c.form(e.key), c.form("PolicyArn"))
		})
		m["ListAttached"+e.word+"Policies"] = spec{params: []string{e.key}, list: true, needsAdmin: true, resource: e.arn, run: func(h *handler, c *exchange) (any, error) {
			ps, err := h.cfg.Admin.ListAttachedPolicies(c.r.Context(), c.caller.Account, kind, c.form(e.key))
			out := attachedResult{AttachedPolicies: []attachedXML{}}
			for _, p := range ps {
				out.AttachedPolicies = append(out.AttachedPolicies, attachedXML{PolicyName: p.Name, PolicyArn: p.ARN})
			}
			return out, err
		}}
		m["Put"+e.word+"Policy"] = admin([]string{e.key, "PolicyName", "PolicyDocument"}, e.arn, func(h *handler, c *exchange) (any, error) {
			if err := required(c, e.key, "PolicyName", "PolicyDocument"); err != nil {
				return nil, err
			}
			return nil, h.cfg.Admin.PutInlinePolicy(c.r.Context(), c.caller.Account, kind, c.form(e.key), c.form("PolicyName"), c.form("PolicyDocument"))
		})
		m["Get"+e.word+"Policy"] = admin([]string{e.key, "PolicyName"}, e.arn, func(h *handler, c *exchange) (any, error) {
			doc, err := h.cfg.Admin.GetInlinePolicy(c.r.Context(), c.caller.Account, kind, c.form(e.key), c.form("PolicyName"))
			out := struct {
				Entity         string `xml:",innerxml"`
				PolicyName     string `xml:"PolicyName"`
				PolicyDocument string `xml:"PolicyDocument"`
			}{PolicyName: c.form("PolicyName"), PolicyDocument: policyDoc(doc)}
			out.Entity = "<" + e.key + ">" + xmlEscape(c.form(e.key)) + "</" + e.key + ">"
			return out, err
		})
		m["Delete"+e.word+"Policy"] = admin([]string{e.key, "PolicyName"}, e.arn, func(h *handler, c *exchange) (any, error) {
			return nil, h.cfg.Admin.DeleteInlinePolicy(c.r.Context(), c.caller.Account, kind, c.form(e.key), c.form("PolicyName"))
		})
		m["List"+e.word+"Policies"] = spec{params: []string{e.key}, list: true, needsAdmin: true, resource: e.arn, run: func(h *handler, c *exchange) (any, error) {
			names, err := h.cfg.Admin.ListInlinePolicies(c.r.Context(), c.caller.Account, kind, c.form(e.key))
			return namesResult{PolicyNames: names}, err
		}}
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
		if r, err := h.cfg.Admin.GetRole(c.r.Context(), c.caller.Account, role); err == nil {
			return r.ID + ":" + session
		}
	}
	if n := userName(c); n != "" {
		if u, err := h.cfg.Admin.GetUser(c.r.Context(), c.caller.Account, n); err == nil && u.ARN == c.caller.Principal {
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
