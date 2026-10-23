package iamquery

import (
	"regexp"
	"strconv"
	"unicode/utf8"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// Request parameters of the user, group and role policy actions, checked as
// the AWS IAM API reference states their constraints.

// attachedPathPrefixRE is the PathPrefix pattern of the ListAttached*Policies
// actions, which is narrower than the one of ListUsers.
var attachedPathPrefixRE = regexp.MustCompile(`^((/[A-Za-z0-9.,+@=_-]+)*)/$`)

// policyDocumentRE is the PolicyDocument character set of the Put*Policy
// actions.
var policyDocumentRE = regexp.MustCompile(`^[\x{0009}\x{000A}\x{000D}\x{0020}-\x{00FF}]+$`)

const (
	minPolicyARN       = 20
	maxPolicyARN       = 2048
	maxPolicyDocument  = 131072
	maxPathPrefixChars = 512
)

func lengthError(field, value, constraint string) error {
	return resource.Invalid(field, "1 validation error detected: Value '"+value+"' at '"+field+
		"' failed to satisfy constraint: Member must have length "+constraint)
}

// policyArnParam reads PolicyArn: 20 to 2048 characters, and an IAM policy
// ARN, or InvalidInput as AWS answers.
func policyArnParam(c *exchange) error {
	if err := required(c, "PolicyArn"); err != nil {
		return err
	}
	arn := c.form("PolicyArn")
	switch n := utf8.RuneCountInString(arn); {
	case n < minPolicyARN:
		return lengthError("policyArn", arn, "greater than or equal to "+strconv.Itoa(minPolicyARN))
	case n > maxPolicyARN:
		return lengthError("policyArn", arn, "less than or equal to "+strconv.Itoa(maxPolicyARN))
	}
	if !policyARNRE.MatchString(arn) {
		return resource.Invalid("PolicyArn", "ARN "+arn+" is not valid.")
	}
	return nil
}

// inlinePolicyNameParam reads PolicyName: 1 to 128 characters of the AWS
// pattern.
func inlinePolicyNameParam(c *exchange) error {
	if err := required(c, "PolicyName"); err != nil {
		return err
	}
	return iam.CheckInlinePolicyName(c.form("PolicyName"))
}

// policyDocumentParam reads PolicyDocument: 1 to 131,072 characters from the
// AWS character set. Its grammar and its size per entity are the backend's.
func policyDocumentParam(c *exchange) error {
	if err := required(c, "PolicyDocument"); err != nil {
		return err
	}
	doc := c.form("PolicyDocument")
	if utf8.RuneCountInString(doc) > maxPolicyDocument {
		return lengthError("policyDocument", "...", "less than or equal to "+strconv.Itoa(maxPolicyDocument))
	}
	if !policyDocumentRE.MatchString(doc) {
		return resource.Invalid("policyDocument", "1 validation error detected: Value at 'policyDocument' "+
			`failed to satisfy constraint: Member must satisfy regular expression pattern: [\u0009\u000A\u000D\u0020-\u00FF]+`)
	}
	return nil
}

// attachedPathPrefixParam reads the PathPrefix of ListAttached*Policies; an
// absent one is "/", every path.
func attachedPathPrefixParam(c *exchange) (string, error) {
	if !c.r.Form.Has("PathPrefix") {
		return "/", nil
	}
	p := c.form("PathPrefix")
	if len(p) > maxPathPrefixChars || !attachedPathPrefixRE.MatchString(p) {
		return "", resource.Invalid("pathPrefix", "1 validation error detected: Value '"+p+
			"' at 'pathPrefix' failed to satisfy constraint: "+
			`Member must satisfy regular expression pattern: ((/[A-Za-z0-9\.,\+@=_-]+)*)/`)
	}
	return p, nil
}
