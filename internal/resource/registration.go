package resource

import "regexp"

// RegistrationFailureMessage permits only classified self-check diagnostics across
// the registration transport and operator status boundary. Upstream errors may
// contain credentials even in their caller-visible fields.
func RegistrationFailureMessage(err error) string {
	if err == nil {
		return ""
	}
	e := AsError(err)
	if e.Code == CodeConflict && e.Message == "cluster_name differs from registration" {
		return e.Message
	}
	if e.Code != CodeUnavailable {
		return ""
	}
	if regexp.MustCompile(`^pool "[A-Za-z0-9][A-Za-z0-9._-]{0,63}": ` +
		`(missing (Pool\.Audit|VM\.Audit)|does not exist|` +
		`privileges could not be verified|existence could not be verified)$`).MatchString(e.Message) {
		return e.Message
	}
	switch e.Message {
	case "registration self-check failed: instance_types",
		"registration self-check failed: privileges",
		"registration self-check failed: cluster_name",
		"registration self-check failed: storages":
		return e.Message
	default:
		return ""
	}
}

// RegionFailureMessage admits operator diagnostics, never upstream response bodies.
func RegionFailureMessage(err error) string {
	if err == nil {
		return ""
	}
	if message := RegistrationFailureMessage(err); message != "" {
		return message
	}
	e := AsError(err)
	if e.Code == CodeUnavailable {
		switch e.Message {
		case "not ready", "region pool check failed", "region status unavailable":
			return e.Message
		}
	}
	return ""
}
