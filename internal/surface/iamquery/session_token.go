package iamquery

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// tokenCodeRE is the AWS TokenCode pattern; SerialNumber reuses
// serialNumberRE.
var tokenCodeRE = regexp.MustCompile(`^\d*$`)

// sessionCredentialsDenied is the AWS answer to GetSessionToken signed with
// temporary credentials.
const sessionCredentialsDenied = "Cannot call GetSessionToken with session credentials"

// getSessionTokenSpec is STS GetSessionToken. AWS requires no permission
// for it and ignores sts:GetSessionToken in policies ("You can include the
// GetSessionToken action in your policies, but it has no effect", IAM User
// Guide, Permissions for GetSessionToken), so like GetCallerIdentity it skips
// Authorize; the signature is still verified, and vws-iam checks the caller
// again from its own authentication.
func getSessionTokenSpec() spec {
	return spec{
		params: []string{"DurationSeconds", "SerialNumber", "TokenCode"}, needsAdmin: true, public: true,
		run: getSessionToken,
	}
}

func getSessionToken(h *handler, c *exchange) (any, error) {
	if temporaryCaller(c) {
		return nil, resource.Denied(sessionCredentialsDenied)
	}
	d, err := sessionTokenInput(c)
	if err != nil {
		return nil, err
	}
	if c.caller.Root && (d == 0 || d > iam.RootSessionTokenDuration) {
		// The account owner's session is at most one hour; a longer request
		// gets one hour, as in AWS.
		d = iam.RootSessionTokenDuration
	}
	caller := iam.Principal{Account: c.caller.Account, ARN: c.caller.Principal, Root: c.caller.Root, Ref: c.caller.Ref}
	k, err := h.cfg.Admin.GetSessionToken(c.r.Context(), caller, d, c.form("SerialNumber"), c.form("TokenCode"))
	if err != nil {
		return nil, err
	}
	return struct {
		Credentials credentialsXML `xml:"Credentials"`
	}{credentialsXML{
		AccessKeyID: k.AccessKey, SecretAccessKey: k.Secret, SessionToken: k.SessionToken, Expiration: stamp(k.Expires),
	}}, nil
}

// temporaryCaller reports a request signed with temporary credentials: a
// security token, an assumed role or an IAM user's console session.
func temporaryCaller(c *exchange) bool {
	return c.r.Header.Get("X-Amz-Security-Token") != "" ||
		c.r.URL.Query().Get("X-Amz-Security-Token") != "" ||
		strings.Contains(c.caller.Principal, ":assumed-role/") ||
		(c.caller.Ref.ProofKind == resource.ProofSession && !c.caller.Root)
}

// sessionTokenInput validates DurationSeconds, SerialNumber and TokenCode
// against the AWS constraints and reports every failure in one
// ValidationError. A zero duration means the default. The token code is a
// secret: its value is never echoed.
func sessionTokenInput(c *exchange) (time.Duration, error) {
	var bad []string
	field := "" // the first member that failed
	fail := func(member, msg string) {
		if field == "" {
			field = member
		}
		bad = append(bad, msg)
	}
	var d time.Duration
	if raw := c.form("DurationSeconds"); raw != "" {
		n, err := strconv.Atoi(raw)
		switch {
		case err != nil || n < int(iam.MinSessionTokenDuration/time.Second):
			fail("durationSeconds", "Value '"+raw+"' at 'durationSeconds' failed to satisfy constraint: "+
				"Member must have value greater than or equal to 900")
		case n > int(iam.MaxSessionTokenDuration/time.Second):
			fail("durationSeconds", "Value '"+raw+"' at 'durationSeconds' failed to satisfy constraint: "+
				"Member must have value less than or equal to 129600")
		default:
			d = time.Duration(n) * time.Second
		}
	}
	if c.r.Form.Has("SerialNumber") {
		s := c.form("SerialNumber")
		prefix := "Value '" + s + "' at 'serialNumber' failed to satisfy constraint: "
		switch {
		case len(s) < 9:
			fail("serialNumber", prefix+"Member must have length greater than or equal to 9")
		case len(s) > 256:
			fail("serialNumber", prefix+"Member must have length less than or equal to 256")
		case !serialNumberRE.MatchString(s):
			fail("serialNumber", prefix+`Member must satisfy regular expression pattern: [\w+=/:,.@-]*`)
		}
	}
	if c.r.Form.Has("TokenCode") {
		s := c.form("TokenCode")
		const prefix = "Value at 'tokenCode' failed to satisfy constraint: "
		switch {
		case len(s) < 6:
			fail("tokenCode", prefix+"Member must have length greater than or equal to 6")
		case len(s) > 6:
			fail("tokenCode", prefix+"Member must have length less than or equal to 6")
		case !tokenCodeRE.MatchString(s):
			fail("tokenCode", prefix+`Member must satisfy regular expression pattern: [\d]*`)
		}
	}
	switch len(bad) {
	case 0:
		return d, nil
	case 1:
		return 0, resource.Invalid(field, "1 validation error detected: "+bad[0])
	default:
		return 0, resource.Invalid(field,
			strconv.Itoa(len(bad))+" validation errors detected: "+strings.Join(bad, "; "))
	}
}
