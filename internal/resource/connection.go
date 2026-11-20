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

// PVEConnectionStepNames returns the four PVE checks the region daemon runs,
// in order. The console adds the regionapi step after them.
func PVEConnectionStepNames() []string {
	return []string{"tls", "version", "cluster_name", "privileges"}
}

var pvePoolMessage = regexp.MustCompile(`^pool "[A-Za-z0-9][A-Za-z0-9._-]{0,63}": ` +
	`(missing (Pool\.Audit|VM\.Audit)|does not exist|privileges could not be verified|existence could not be verified)$`)

// pveStepMessage reports whether message is one the daemon writes for step i
// with that result.
func pveStepMessage(i int, result ConnectionResult, message string) bool {
	passed := [4]string{
		"PVE TLS certificate verified", "PVE version read succeeded", "cluster_name accepted",
		"token privileges are read-only",
	}
	failed := [4][]string{
		{"PVE TLS handshake failed"},
		{"PVE version read failed"},
		{"cluster_name differs or could not be verified"},
		{"token permissions could not be verified", "token holds a privilege outside PVEAuditor read-only access"},
	}
	if result == ConnectionPass {
		return message == passed[i]
	}
	return slices.Contains(failed[i], message) || i == 3 && pvePoolMessage.MatchString(message)
}

// ValidPVEConnectionSteps accepts only the daemon's ordered result: passes,
// then at most one failure, then skips, each with a fixed or classified
// message. A reply that fails this cannot publish upstream text.
func ValidPVEConnectionSteps(steps []ConnectionStep) bool {
	names := PVEConnectionStepNames()
	if len(steps) != len(names) {
		return false
	}
	failed := false
	for i, step := range steps {
		if step.Name != names[i] {
			return false
		}
		switch {
		case failed:
			if step.Result != ConnectionSkipped || step.Message != "previous step failed" {
				return false
			}
		case step.Result == ConnectionPass || step.Result == ConnectionFail:
			failed = step.Result == ConnectionFail
			if !pveStepMessage(i, step.Result, step.Message) {
				return false
			}
		default:
			return false
		}
	}
	return true
}
