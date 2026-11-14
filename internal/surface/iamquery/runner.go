package iamquery

import (
	"context"
	"crypto/sha256"
	"net/http"
	"net/url"
	"slices"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
)

// Input is one IAM action and its Query parameters, without Action or Version.
type Input struct {
	Action string
	Params url.Values
}

// Operation is validated and authorized for one caller and one resource snapshot.
// Prepare must run on every request, including a replay of a previous create.
type Operation struct {
	h    *handler
	c    *exchange
	spec spec
	arn  string
}

// Runner shares an action table across calls from an authenticated surface.
type Runner struct{ h *handler }

// NewRunner wires an in-process IAM action runner.
func NewRunner(cfg Config) *Runner {
	return &Runner{h: &handler{cfg: cfg, actions: actionTable()}}
}

// ARN is the resource resolved by the action table.
func (o *Operation) ARN() string { return o.arn }

// Fingerprint hashes the canonical action parameters without retaining secrets.
func (o *Operation) Fingerprint() [32]byte { return sha256.Sum256([]byte(o.c.r.Form.Encode())) }

// Run invokes the action with its authorized resource binding.
func (o *Operation) Run() (any, error) { return o.spec.run(o.h, o.c) }

// Prepare accepts a caller authenticated by another surface. It applies the
// same validation and authorization as a verified SigV4 request.
func (runner *Runner) Prepare(ctx context.Context, caller resource.Caller, in Input) (*Operation, error) {
	form := make(url.Values, len(in.Params)+2)
	for k, values := range in.Params {
		form[k] = slices.Clone(values)
	}
	form.Add("Action", in.Action)
	form.Add("Version", IAMVersion)
	r := (&http.Request{Form: form}).WithContext(ctx)
	return runner.h.prepare(ctx, &exchange{r: r, caller: caller, service: sigv4.ServiceIAM})
}

func (h *handler) prepare(ctx context.Context, c *exchange) (*Operation, error) {
	r := c.r
	if err := r.ParseForm(); err != nil {
		return nil, resource.Invalid("body", "malformed form")
	}
	for k, vs := range r.Form {
		if len(vs) > 1 {
			return nil, resource.Invalid(k, "repeated")
		}
	}
	for _, k := range [...]string{"PolicyArn", "RoleArn", "SerialNumber"} {
		if vs := r.Form[k]; len(vs) == 1 {
			vs[0] = iam.VWSPartition(vs[0])
		}
	}
	for _, k := range [...]string{"PolicyDocument", "AssumeRolePolicyDocument"} {
		if arn, ok := awsARNIn(r.Form.Get(k)); ok {
			return nil, resource.Invalid("PolicyDocument", `Partition "aws" is not valid for resource "`+arn+
				`": policies are evaluated in the vws partition (#681).`)
		}
	}
	want := IAMVersion
	if c.service == sigv4.ServiceSTS {
		want = STSVersion
	}
	if r.Form.Get("Version") != want {
		return nil, resource.Invalid("Version", "unsupported API version")
	}
	c.action = r.Form.Get("Action")
	s, ok := h.actions[c.service][c.action]
	if !ok || (h.cfg.Admin == nil && s.needsAdmin) {
		return nil, resource.Unimplemented("Could not find operation " + c.action)
	}
	for k := range r.Form {
		if k != "Action" && k != "Version" && !s.allows(k) {
			return nil, resource.Invalid(k, "Parameter "+k+" is not supported")
		}
	}
	if slices.Contains(s.params, "UserName") {
		if err := validateUserName(c); err != nil {
			return nil, err
		}
	}
	arn := "*"
	if s.resource != nil {
		arn = s.resource(h, c)
		if c.resourceErr != nil {
			return nil, c.resourceErr
		}
	}
	if !s.public {
		authorized, err := iam.Authorize(ctx, h.cfg.Authorizer, c.caller, string(c.service)+":"+c.action, arn)
		if err != nil {
			return nil, err
		}
		c.authorized = authorized
	}
	return &Operation{h: h, c: c, spec: s, arn: arn}, nil
}

// ErrorCode returns the IAM Query status and code for a domain error.
func ErrorCode(action string, err error) (int, string) {
	return (&exchange{service: sigv4.ServiceIAM, action: action}).wire(resource.AsError(err))
}
