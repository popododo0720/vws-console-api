package resource

import (
	"regexp"
	"slices"
	"strings"
)

// ConnectionResult is the outcome of one ordered connection check.
type ConnectionResult string

// Connection check outcomes.
const (
	ConnectionPass    ConnectionResult = "PASS"
	ConnectionFail    ConnectionResult = "FAIL"
	ConnectionSkipped ConnectionResult = "SKIPPED"
)

// ConnectionStep contains only safe diagnostics, never upstream response text.
type ConnectionStep struct {
	Name    string           `json:"name"`
	Result  ConnectionResult `json:"result"`
	Message string           `json:"message"`
}

// AWSConnectionRequest crosses the private socket without AWS source or session credentials.
type AWSConnectionRequest struct {
	AccountID  string `json:"awsAccountId"`
	RoleARN    string `json:"roleArn"`
	ExternalID string `json:"externalId"`
}

// ValidateAWSAccount keeps registration and private diagnostic boundary rules identical.
func ValidateAWSAccount(account, arn string, external *string, required bool) error {
	if !regexp.MustCompile(`^[0-9]{12}$`).MatchString(account) {
		return Invalid("awsAccountId", "must be 12 digits")
	}
	role, ok := strings.CutPrefix(arn, "arn:aws:iam::"+account+":role/")
	path, name := "", role
	if i := strings.LastIndex(role, "/"); i >= 0 {
		path, name = "/"+role[:i+1], role[i+1:]
	}
	if !ok || len(arn) > 2048 || len(path) > 512 ||
		!regexp.MustCompile(`^[\w+=,.@-]{1,64}$`).MatchString(name) ||
		(path != "" && !regexp.MustCompile(`^/[\x21-\x7e]+/$`).MatchString(path)) {
		return Invalid("roleArn", "must name an IAM role in awsAccountId")
	}
	if required && external == nil || external != nil &&
		(len(*external) < 2 || len(*external) > 1224 || !regexp.MustCompile(`^[\w+=,.@:/-]+$`).MatchString(*external)) {
		return Invalid("externalId", "must be 2 to 1224 STS ExternalId characters")
	}
	return nil
}

// AWSConnectionSteps contains fixed diagnostics so upstream text cannot escape through errors.
func AWSConnectionSteps(assumed, matched bool) []ConnectionStep {
	steps := []ConnectionStep{
		{Name: "assume_role", Result: ConnectionFail, Message: "AssumeRole failed"},
		{Name: "get_caller_identity", Result: ConnectionSkipped, Message: "previous step failed"},
	}
	if assumed {
		steps[0].Result, steps[0].Message = ConnectionPass, "AssumeRole succeeded"
		steps[1].Result, steps[1].Message = ConnectionFail, "AWS account identity check failed"
		if matched {
			steps[1].Result, steps[1].Message = ConnectionPass, "AWS account identity matched"
		}
	}
	return steps
}

// ValidAWSConnectionSteps rejects proxy replies that could publish upstream text or secrets.
func ValidAWSConnectionSteps(steps []ConnectionStep) bool {
	if len(steps) != 2 || steps[0].Name != "assume_role" || steps[1].Name != "get_caller_identity" {
		return false
	}
	first, last := steps[0], steps[1]
	if first.Result == ConnectionFail {
		return slices.Contains([]string{
			"AssumeRole was denied; check the role trust policy and ExternalId",
			"STS rejected the proxy source credentials", "STS rejected the AssumeRole request",
			"STS unavailable", "STS returned an unusable response",
		}, first.Message) && last.Result == ConnectionSkipped && last.Message == "previous step failed"
	}
	if first.Result != ConnectionPass || first.Message != "AssumeRole succeeded" {
		return false
	}
	return last.Result == ConnectionPass && last.Message == "AWS account identity matched" ||
		last.Result == ConnectionFail && slices.Contains([]string{
			"caller identity is in another account", "STS rejected the session credentials",
			"STS unavailable", "STS returned an unusable response",
		}, last.Message)
}
