package iam

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// policyStatement is one parsed statement of a JSON policy document.
type policyStatement struct {
	effect      Effect
	action      []string
	notAction   []string
	resource    []string
	notResource []string
	principals  []string // AWS principal ARNs or account ids; "*" for anyone
	condition   bool
}

// maxPolicyBytes is AWS's managed-policy document limit.
const maxPolicyBytes = 6144

type stringList []string

func (l *stringList) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*l = []string{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err //nolint:wrapcheck // Reported as MalformedPolicyDocument.
	}
	*l = many
	return nil
}

type rawStatement struct {
	Sid          string          `json:"Sid"`          //nolint:tagliatelle // AWS policy grammar is PascalCase.
	Effect       string          `json:"Effect"`       //nolint:tagliatelle // AWS policy grammar is PascalCase.
	Action       *stringList     `json:"Action"`       //nolint:tagliatelle // AWS policy grammar is PascalCase.
	NotAction    *stringList     `json:"NotAction"`    //nolint:tagliatelle // AWS policy grammar is PascalCase.
	Resource     *stringList     `json:"Resource"`     //nolint:tagliatelle // AWS policy grammar is PascalCase.
	NotResource  *stringList     `json:"NotResource"`  //nolint:tagliatelle // AWS policy grammar is PascalCase.
	Principal    json.RawMessage `json:"Principal"`    //nolint:tagliatelle // AWS policy grammar is PascalCase.
	NotPrincipal json.RawMessage `json:"NotPrincipal"` //nolint:tagliatelle // AWS policy grammar is PascalCase.
	Condition    json.RawMessage `json:"Condition"`    //nolint:tagliatelle // AWS policy grammar is PascalCase.
}

type rawPolicy struct {
	Version   string          `json:"Version"`   //nolint:tagliatelle // AWS policy grammar is PascalCase.
	ID        string          `json:"Id"`        //nolint:tagliatelle // AWS policy grammar is PascalCase.
	Statement json.RawMessage `json:"Statement"` //nolint:tagliatelle // AWS policy grammar is PascalCase.
}

func malformed(msg string) error {
	return &resource.Error{Code: resource.CodeInvalidArgument, Field: "PolicyDocument", Message: msg}
}

// parsePolicy reads an identity policy (trust=false: no Principal, Resource
// required) or a role trust policy (trust=true: Principal required, no
// Resource). Unknown top-level or statement keys are rejected.
func parsePolicy(doc string, trust bool) ([]policyStatement, error) {
	if len(doc) > maxPolicyBytes {
		return nil, &resource.Error{Code: resource.CodeResourceExhausted, Field: "PolicyDocument", Message: "Cannot exceed quota for PolicySize: 6144"}
	}
	return parseDoc(doc, trust)
}

// parseDoc is parsePolicy without the managed policy size limit, for inline
// policies, whose size AWS counts per entity.
func parseDoc(doc string, trust bool) ([]policyStatement, error) {
	var p rawPolicy
	dec := json.NewDecoder(strings.NewReader(doc))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil || dec.More() {
		return nil, malformed("Syntax errors in policy.")
	}
	if p.Version != "" && p.Version != "2012-10-17" && p.Version != "2008-10-17" {
		return nil, malformed("The policy failed legacy parsing")
	}
	var raws []rawStatement
	trimmed := bytes.TrimSpace(p.Statement)
	switch {
	case len(trimmed) == 0:
		return nil, malformed("Policy document must contain a Statement")
	case trimmed[0] == '{':
		var one rawStatement
		if err := strictUnmarshal(trimmed, &one); err != nil {
			return nil, malformed("Syntax errors in policy.")
		}
		raws = []rawStatement{one}
	default:
		if err := strictUnmarshal(trimmed, &raws); err != nil {
			return nil, malformed("Syntax errors in policy.")
		}
	}
	if len(raws) == 0 {
		return nil, malformed("Policy document must contain a Statement")
	}
	out := make([]policyStatement, 0, len(raws))
	for _, r := range raws {
		s, err := convert(r, trust)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

func strictUnmarshal(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	return dec.Decode(v) //nolint:wrapcheck // Reported as MalformedPolicyDocument.
}

func convert(r rawStatement, trust bool) (policyStatement, error) {
	s := policyStatement{effect: Effect(r.Effect), condition: len(r.Condition) > 0}
	if s.effect != Allow && s.effect != Deny {
		return s, malformed("Invalid effect: " + r.Effect)
	}
	if (r.Action == nil) == (r.NotAction == nil) {
		return s, malformed("Policy statement must contain exactly one of Action or NotAction")
	}
	if r.Action != nil {
		s.action = *r.Action
	} else {
		s.notAction = *r.NotAction
	}
	for _, a := range append(append([]string(nil), s.action...), s.notAction...) {
		if a != "*" && !strings.Contains(a, ":") {
			return s, malformed("Actions/Conditions must be prefaced by a vendor, e.g., iam, sdb, ec2, etc.")
		}
	}
	if len(r.NotPrincipal) > 0 {
		return s, malformed("NotPrincipal is not supported")
	}
	if trust {
		if len(r.Principal) == 0 {
			return s, malformed("AssumeRolepolicy contained an invalid principal")
		}
		if r.Resource != nil || r.NotResource != nil {
			return s, malformed("Has prohibited field Resource")
		}
		p, err := parsePrincipal(r.Principal)
		if err != nil {
			return s, err
		}
		s.principals = p
		return s, nil
	}
	if len(r.Principal) > 0 {
		return s, malformed("Policy document should not specify a principal.")
	}
	if (r.Resource == nil) == (r.NotResource == nil) {
		return s, malformed("Policy statement must contain exactly one of Resource or NotResource")
	}
	if r.Resource != nil {
		s.resource = *r.Resource
	} else {
		s.notResource = *r.NotResource
	}
	return s, nil
}

// parsePrincipal reads "*" or {"AWS": "arn"|[...]}; Service and Federated
// principals parse but never match a console-api caller.
func parsePrincipal(raw json.RawMessage) ([]string, error) {
	var star string
	if err := json.Unmarshal(raw, &star); err == nil {
		if star != "*" {
			return nil, malformed("Invalid principal in policy")
		}
		return []string{"*"}, nil
	}
	var m map[string]stringList
	if err := json.Unmarshal(raw, &m); err != nil || len(m) == 0 {
		return nil, malformed("Invalid principal in policy")
	}
	for k := range m {
		if k != "AWS" && k != "Service" && k != "Federated" {
			return nil, malformed("Invalid principal in policy")
		}
	}
	return m["AWS"], nil
}

// applies reports whether s covers action on res. Allow statements with a
// Condition never apply (conditions are evaluated by vws-iam, not the fake),
// and Deny statements with one always do: the fake errs toward denying.
func (s policyStatement) applies(action, res string) bool {
	if s.condition && s.effect == Allow {
		return false
	}
	if s.action != nil && !matchAny(s.action, action, true) {
		return false
	}
	if s.notAction != nil && matchAny(s.notAction, action, true) {
		return false
	}
	if s.resource != nil && !matchAny(s.resource, res, false) {
		return false
	}
	if s.notResource != nil && matchAny(s.notResource, res, false) {
		return false
	}
	return true
}

// trustAdmits evaluates a role trust policy for sts:AssumeRole by caller:
// explicit deny, then allow, then implicit deny. Naming the account (its id or
// root ARN) admits any principal in it. A statement with a Condition is
// treated as in applies: Allow never applies, Deny always does.
func trustAdmits(stmts []policyStatement, caller Principal) bool {
	allowed := false
	for _, s := range stmts {
		if s.action != nil && !matchAny(s.action, "sts:AssumeRole", true) {
			continue
		}
		if s.notAction != nil && matchAny(s.notAction, "sts:AssumeRole", true) {
			continue
		}
		if !namesPrincipal(s.principals, caller) {
			continue
		}
		if s.effect == Deny {
			return false
		}
		if !s.condition {
			allowed = true
		}
	}
	return allowed
}

func namesPrincipal(principals []string, caller Principal) bool {
	for _, p := range principals {
		if p == "*" || p == caller.ARN || p == caller.Account.String() || p == RootARN(caller.Account) {
			return true
		}
	}
	return false
}

// evaluate is AWS identity-policy logic: explicit deny, then allow, then
// implicit deny.
func evaluate(stmts []policyStatement, action, res string) Decision {
	allowed := false
	for _, s := range stmts {
		if !s.applies(action, res) {
			continue
		}
		if s.effect == Deny {
			return Decision{Reason: "explicit deny"}
		}
		allowed = true
	}
	if allowed {
		return Decision{Allowed: true, Reason: "allowed by identity policy"}
	}
	return Decision{Reason: "implicit deny"}
}
